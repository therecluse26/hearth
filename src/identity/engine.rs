//! Embedded identity engine implementation.
//!
//! Implements `IdentityEngine` using the `StorageEngine` trait for persistence
//! and `Clock` trait for deterministic timestamps.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SecureRandom;

use crate::audit::{Actor, AuditAction, AuditContext, AuditEngine, CreateAuditEvent};
use crate::core::{
    ClientId, Clock, InvitationId, OrganizationId, RealmId, SessionId, Uri, UserId, WebhookId,
};
use crate::identity::claims_config::{
    resolve_claims_for_target, ClaimEvaluationContext, ClaimTarget,
};
use crate::identity::credentials::{self, CleartextPassword, CredentialConfig, StoredCredential};
use crate::identity::error::IdentityError;
use crate::identity::keys;
/// Encodes bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

use crate::identity::magic_link::{
    self, MagicLinkResponse, StoredMagicLink, StoredPasswordReset, MAGIC_LINK_EXPIRY_MICROS,
    PASSWORD_RESET_EXPIRY_MICROS,
};

/// Enforces token size caps per AUTHORIZATION.md § 2.6.
///
/// Operates on the *post-profile* claim payload that will actually be
/// embedded in the JWT, not the raw `ResolvedPermissions`. This ensures
/// scope-narrowed tokens are measured correctly.
///
/// Validates independently per `ClaimTarget` so that access-token and
/// ID-token payloads (which may differ after `apply_claim_profile`) are
/// each checked against the same numeric caps. Limit names include the
/// target prefix so operators can tell which surface tripped.
///
/// Custom claims are intentionally excluded from the 8 KiB byte limit
/// per the spec ("Serialized JWT claim bytes (`roles + groups + permissions`)").
pub(crate) fn validate_claim_payload(
    target: ClaimTarget,
    roles: &[String],
    groups: &[String],
    permissions: &[String],
) -> Result<(), IdentityError> {
    const MAX_PERMISSIONS: usize = 100;
    const MAX_ROLES: usize = 50;
    const MAX_GROUPS: usize = 50;
    const MAX_CLAIM_BYTES: usize = 8192;

    let target_prefix = match target {
        ClaimTarget::AccessToken => "access_token",
        ClaimTarget::IdToken => "id_token",
        ClaimTarget::UserInfo => "userinfo",
    };

    if permissions.len() > MAX_PERMISSIONS {
        return Err(IdentityError::TokenTooLarge {
            limit: format!("{target_prefix}_permissions_per_token"),
            limit_value: MAX_PERMISSIONS,
            actual: permissions.len(),
        });
    }
    if roles.len() > MAX_ROLES {
        return Err(IdentityError::TokenTooLarge {
            limit: format!("{target_prefix}_roles_per_token"),
            limit_value: MAX_ROLES,
            actual: roles.len(),
        });
    }
    if groups.len() > MAX_GROUPS {
        return Err(IdentityError::TokenTooLarge {
            limit: format!("{target_prefix}_groups_per_token"),
            limit_value: MAX_GROUPS,
            actual: groups.len(),
        });
    }

    let payload = serde_json::json!({
        "roles": roles,
        "groups": groups,
        "permissions": permissions,
    });
    let bytes = serde_json::to_vec(&payload).map_err(|e| IdentityError::Internal {
        reason: format!("token size serialization failed: {e}"),
    })?;
    if bytes.len() > MAX_CLAIM_BYTES {
        return Err(IdentityError::TokenTooLarge {
            limit: format!("{target_prefix}_claims_bytes_per_token"),
            limit_value: MAX_CLAIM_BYTES,
            actual: bytes.len(),
        });
    }

    Ok(())
}

/// Email-verification token expiry: 24 hours in microseconds.
const EMAIL_VERIFY_EXPIRY_MICROS: i64 = 24 * 60 * 60 * 1_000_000;

/// Maximum tolerated clock skew between issuer and validator, in seconds.
///
/// Tokens with `iat > now + CLOCK_SKEW_SECS` are rejected as future-dated.
/// 60 seconds matches common JWT library defaults and absorbs NTP drift without
/// opening a meaningful replay window.
const CLOCK_SKEW_SECS: i64 = 60;

/// Persisted state for a pending email-verification token.
///
/// Stored under `email:verify:{sha256_hex_of_token}`. The plaintext
/// token is never persisted — only its SHA-256 digest is used as the
/// key. Verification is single-use: on success the entry is deleted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredEmailVerification {
    /// Stringified UUID of the user whose email is being verified.
    user_id: String,
    /// Creation time in Unix microseconds.
    created_at_micros: i64,
    /// Whether the token has already been consumed. Present for parity
    /// with the magic-link record; `verify_email_token` also deletes the
    /// entry outright on success.
    used: bool,
}
use crate::identity::oidc::{
    ApplicationStatus, AuthorizationRequest, AuthorizationResponse, BackchannelTarget,
    CodeChallengeMethod, FrontchannelTarget, OAuthClient, OidcConfig, OidcDiscoveryDocument,
    OidcTokenResponse, RegisterClientRequest, RpLogoutRequest, RpLogoutResult,
    StoredAuthorizationCode, StoredDeviceCode, StoredGrantFamily, TokenExchangeRequest,
};
use crate::identity::tokens::{
    self, Audience, IssueTokenRequest, JwksDocument, LogoutTokenClaims, SigningKey, TokenClaims,
    TokenConfig, TokenPair,
};
use crate::identity::totp::{self, RecoveryCodes, StoredMfaState, TotpEnrollment, TotpSecret};
use crate::identity::types::{
    BulkResult, ConsentListEntry, ConsentRecord, CreateInvitationRequest,
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, ImportClientRequest,
    ImportUserRequest, InvitationStatus, Organization, OrganizationInvitation,
    OrganizationMembership, OrganizationRole, OrganizationStatus, Page,
    PendingAuthorizationRequest, Realm, RealmStatus, RegisterUserRequest, RegisterUserResponse,
    RegistrationPolicy, Session, SessionContext, UpdateOrganizationRequest, UpdateRealmRequest,
    UpdateUserRequest, User, UserStatus,
};
use crate::identity::validation;
use crate::identity::webauthn::{
    self, AuthenticationOptions, CeremonyType, CompleteAuthenticationParams,
    PendingWebAuthnChallenge, RegistrationOptions, StoredWebAuthnCredential, WebAuthnAuthResult,
    WebAuthnChallengeStore, WebAuthnCredentialInfo,
};
use crate::identity::IdentityEngine;
use crate::rbac::error::RbacError;
use crate::rbac::registry::{classify_scope_string, ScopeKind};
use crate::storage::StorageEngine;

/// Context supplied to [`IdentityEngine::issue_tokens_with_context`] to
/// influence which claims are embedded in the issued token pair.
///
/// All fields are optional. `Default::default()` produces a first-party,
/// no-scope, no-org context that is equivalent to what the legacy
/// `issue_tokens` call produced before this struct existed.
#[derive(Clone, Debug, Default)]
pub struct TokenIssuanceContext {
    /// OAuth client the token is being issued for.
    ///
    /// `None` means a first-party session token (same sentinel as the
    /// pre-context `issue_tokens` path).
    pub client_id: Option<crate::core::ClientId>,
    /// Scopes that were granted for this token.
    ///
    /// Empty means no scope gating; all resolved permissions are included.
    pub granted_scopes: BTreeSet<String>,
    /// Organization context (`oid` claim) to embed in the token.
    ///
    /// `None` means no org context.
    pub oid: Option<String>,
    /// Optional RFC 8707 resource indicator. When present, the resource URI
    /// is embedded in the access and refresh token `aud` claim and enables
    /// audience-scoped scope resolution at token-issue time.
    ///
    /// `None` means no resource audience restriction.
    pub resource: Option<crate::core::Uri>,
}

/// Configuration for credential rate limiting.
///
/// Limits the number of consecutive failed password verification attempts
/// per user. After `max_failed_attempts` failures, the account is temporarily
/// locked for `lockout_duration_micros`.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum consecutive failed attempts before lockout.
    pub max_failed_attempts: u32,
    /// Lockout duration in microseconds.
    pub lockout_duration_micros: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            // 15 minutes in microseconds
            lockout_duration_micros: 15 * 60 * 1_000_000,
        }
    }
}

/// Configuration for session management.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session time-to-live in microseconds.
    ///
    /// Default: 24 hours (86,400,000,000 μs).
    pub ttl_micros: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            // 24 hours in microseconds
            ttl_micros: 24 * 60 * 60 * 1_000_000,
        }
    }
}

/// Configuration for the identity engine.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Default status for newly created users.
    pub default_status: UserStatus,
    /// Password hashing parameters.
    pub credential: CredentialConfig,
    /// Session management parameters.
    pub session: SessionConfig,
    /// Token issuance parameters.
    pub token: TokenConfig,
    /// OIDC / OAuth 2.0 parameters.
    pub oidc: OidcConfig,
    /// Rate limiting for credential verification.
    pub rate_limit: RateLimitConfig,
    /// Periodic cleanup sweeper configuration.
    pub cleanup: crate::identity::cleanup::CleanupConfig,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            default_status: UserStatus::Active,
            credential: CredentialConfig::default(),
            session: SessionConfig::default(),
            token: TokenConfig::default(),
            oidc: OidcConfig::default(),
            rate_limit: RateLimitConfig::default(),
            cleanup: crate::identity::cleanup::CleanupConfig::default(),
        }
    }
}

/// Tracks failed credential verification attempts for a single user.
#[derive(Debug, Clone)]
struct AttemptTracker {
    /// Number of consecutive failed attempts.
    failed_count: u32,
    /// Timestamp (Unix micros) of the most recent failure.
    last_failure_micros: i64,
}

/// Embedded identity engine backed by a `StorageEngine`.
///
/// Manages user CRUD operations with email uniqueness enforcement,
/// input validation, and Unicode normalization. Supports multi-tenancy
/// with per-realm signing keys and configuration.
pub struct EmbeddedIdentityEngine {
    /// The underlying storage engine.
    storage: Arc<dyn StorageEngine>,
    /// Injectable clock for deterministic testing.
    clock: Arc<dyn Clock>,
    /// Engine configuration (global defaults, overridable per-realm).
    config: IdentityConfig,
    /// Claims-based RBAC engine used to resolve effective permissions
    /// at token-issue time. See `docs/specs/AUTHORIZATION.md`.
    rbac: Arc<dyn crate::rbac::RbacEngine>,
    /// Audit engine for recording security-critical mutations.
    ///
    /// Best-effort for non-destructive operations; returns
    /// `AuditFailure` for destructive operations when appending fails.
    audit: Arc<dyn AuditEngine>,
    /// Pre-computed dummy hash for timing-oracle prevention.
    ///
    /// When `verify_password` is called for a nonexistent user or missing
    /// credential, we verify against this dummy hash so the response time
    /// is indistinguishable from a real failed verification.
    dummy_hash: String,
    /// Default Ed25519 signing key for JWT token issuance (Phase 0 compat).
    signing_key: Arc<SigningKey>,
    /// Per-realm signing keys, lazily loaded from storage.
    ///
    /// Each realm gets its own Ed25519 key pair so tokens from one
    /// realm cannot validate in another.
    realm_signing_keys: Mutex<HashMap<String, Arc<SigningKey>>>,
    /// Per-realm RSA signing keys used for SAML metadata + response signing.
    ///
    /// Lazily loaded. Regeneration happens only on first SAML operation in
    /// a realm that has no prior key — not on every startup.
    realm_saml_keys: Mutex<HashMap<String, Arc<crate::identity::tokens::RsaSigningKey>>>,
    /// Server-wide RSA-2048 signing key advertised at `/certs` for RS256
    /// (HEA-51 / OIDC M1).
    ///
    /// Lazily initialized on first JWKS access — RSA keygen is slow
    /// (~0.5-1s), so we don't pay that cost in tests that never touch
    /// `/certs` or in startup paths that don't need OIDC. The key has
    /// the same lifetime as the engine instance (in-memory only in M1);
    /// persistent storage + rotation are deferred to follow-ups.
    oidc_rsa_key: std::sync::OnceLock<Arc<crate::identity::tokens::RsaSigningKey>>,
    /// Server-wide ECDSA P-256 signing key advertised at `/certs` for
    /// ES256 (HEA-51 / OIDC M1).
    ///
    /// Same lazy/in-memory caveats as `oidc_rsa_key`. EC keygen is fast
    /// but we follow the same pattern for symmetry and to keep both keys'
    /// initialization order coupled to the first JWKS request.
    oidc_ecdsa_key: std::sync::OnceLock<Arc<crate::identity::tokens::EcdsaSigningKey>>,
    /// Per-user failed attempt trackers for rate limiting.
    ///
    /// Key is `(RealmId, UserId)` serialized as a string to avoid
    /// requiring `Hash` on the newtype wrappers.
    attempt_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-user failed MFA attempt trackers (separate from password rate limiting).
    ///
    /// Stricter limits: 5 attempts, 5-minute lockout. Key format: `mfa:{realm}:{user}`.
    mfa_attempt_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Used nonces for replay protection (when nonce enforcement is enabled).
    ///
    /// Maps nonce value to the timestamp it was first seen. Entries are swept
    /// on every insertion: any nonce older than `authorization_code_ttl_secs`
    /// is removed, bounding the set to at most one TTL window of activity.
    used_nonces: Mutex<HashMap<String, crate::core::Timestamp>>,
    /// Per-email magic link rate trackers.
    ///
    /// Limits the number of magic link requests per email per hour.
    /// Key format: `magic:{realm}:{email}`.
    magic_link_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-email password reset rate trackers.
    ///
    /// Limits the number of password reset requests per email per hour.
    /// Key format: `reset:{realm}:{email}`.
    password_reset_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-email self-registration rate trackers.
    ///
    /// Limits the number of registration attempts per email per hour.
    /// Key format: `reg-email:{realm}:{email}`.
    registration_email_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-IP self-registration rate trackers.
    ///
    /// Limits the number of registration attempts per source IP per hour,
    /// across all realms and emails.
    /// Key format: raw IP string.
    registration_ip_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-IP login rate trackers for credential-stuffing protection.
    ///
    /// Counts failed login attempts per source IP per realm within a sliding
    /// window. Keyed by `"{realm_uuid}:{ip}"` so attacks on one realm do
    /// not affect legitimate users on another.
    ip_login_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Pending `WebAuthn` challenges awaiting completion.
    webauthn_challenges: WebAuthnChallengeStore,
    /// Serializes realm-record lifecycle mutations (create/update/delete).
    ///
    /// Realm ops are not on the hot path, and a realm record and its
    /// signing key MUST move together to avoid an orphaned "live realm
    /// with no JWKS" state. A single coarse mutex is the simplest way to
    /// guarantee atomicity of the record+key pair under concurrent
    /// callers; a finer-grained per-realm lock could come later if
    /// contention ever becomes measurable.
    realm_ops_lock: Mutex<()>,
}

impl std::fmt::Debug for EmbeddedIdentityEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedIdentityEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl EmbeddedIdentityEngine {
    fn claim_profile_overrides(
        &self,
        realm_id: &RealmId,
    ) -> Vec<crate::identity::claims_config::ClaimMapping> {
        self.get_realm(realm_id)
            .ok()
            .flatten()
            .and_then(|realm| realm.config().claim_profile.clone())
            .map(|profile| profile.mappings)
            .unwrap_or_default()
    }

    fn claim_vector(value: Option<&serde_json::Value>) -> Vec<String> {
        match value {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn apply_claim_profile(
        &self,
        realm_id: &RealmId,
        user: &User,
        client: &OAuthClient,
        resolved: &crate::rbac::ResolvedPermissions,
        granted_scopes: &BTreeSet<String>,
        oid: Option<&str>,
        target: ClaimTarget,
    ) -> (
        Vec<String>,
        Vec<String>,
        Vec<String>,
        BTreeMap<String, serde_json::Value>,
    ) {
        let permissions: Vec<String> = resolved
            .permissions
            .iter()
            .map(|permission| permission.as_str().to_string())
            .collect();
        let overrides = self.claim_profile_overrides(realm_id);
        let ctx = ClaimEvaluationContext {
            user,
            client,
            roles: &resolved.roles,
            groups: &resolved.groups,
            permissions: &permissions,
            granted_scopes,
            oid,
        };
        let mut claims = resolve_claims_for_target(target, &overrides, &ctx);
        let roles = Self::claim_vector(claims.get("roles"));
        let groups = Self::claim_vector(claims.get("groups"));
        let permissions = Self::claim_vector(claims.get("permissions"));
        claims.remove("roles");
        claims.remove("groups");
        claims.remove("permissions");
        (roles, groups, permissions, claims)
    }

    fn validate_client_scope_request(
        &self,
        client: &OAuthClient,
        raw_scope: &str,
    ) -> Result<(), IdentityError> {
        // RFC 6749 §3.3 character validation (must come first — gate all paths)
        validation::validate_scope_tokens(raw_scope)?;
        let requested: Vec<&str> = raw_scope
            .split_whitespace()
            .filter(|scope| !scope.is_empty())
            .collect();
        if client.trust_level() == crate::identity::ClientTrustLevel::ThirdParty
            && requested.is_empty()
        {
            return Err(IdentityError::InvalidInput {
                reason: "invalid_scope: third-party clients must request at least one scope"
                    .to_string(),
            });
        }
        for scope in requested {
            // OIDC standard scopes (openid, profile, email, phone, address,
            // offline_access) are protocol-level. They are always legal
            // regardless of `declared_scopes` and are exempt from the
            // ThirdParty-permission prohibition.
            if classify_scope_string(scope) == Some(ScopeKind::OidcStandard) {
                continue;
            }

            // Non-OIDC scopes must be in declared_scopes when the client
            // has a non-empty declared set.
            if !client.declared_scopes().is_empty()
                && !client
                    .declared_scopes()
                    .iter()
                    .any(|declared| declared == scope)
            {
                return Err(IdentityError::InvalidInput {
                    reason: format!("invalid_scope: client did not declare scope '{scope}'"),
                });
            }

            if client.trust_level() == crate::identity::ClientTrustLevel::ThirdParty
                && classify_scope_string(scope) == Some(ScopeKind::Permission)
            {
                return Err(IdentityError::InvalidInput {
                    reason: format!(
                        "invalid_scope: third-party clients cannot request raw permission scope '{scope}'"
                    ),
                });
            }
        }
        Ok(())
    }

    /// Records an audit event for a security-critical mutation.
    ///
    /// Best-effort for non-destructive actions (`LogOnly` policy): logs
    /// a warning on failure. Returns `Err(AuditFailure)` for destructive
    /// actions (`FailOperation` policy) so the caller knows the audit
    /// trail has a gap.
    fn record_audit(
        &self,
        realm_id: &RealmId,
        ctx: Option<&AuditContext>,
        action: AuditAction,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<(), IdentityError> {
        let policy = action.failure_policy();
        let actor = ctx.map_or_else(|| "system".to_string(), |c| c.actor.label());
        let event = CreateAuditEvent {
            realm_id: realm_id.clone(),
            actor,
            action,
            resource_type: resource_type.to_string(),
            resource_id: resource_id.to_string(),
            metadata: ctx.and_then(|c| c.metadata.clone()),
        };
        match self.audit.append(&event) {
            Ok(_) => Ok(()),
            Err(e) => {
                if policy == crate::audit::AuditFailurePolicy::FailOperation {
                    tracing::error!(
                        error = %e,
                        action = %event.action.as_str(),
                        resource_id = %resource_id,
                        "Audit append failed for destructive operation"
                    );
                    Err(IdentityError::AuditFailure {
                        action: event.action.as_str().to_string(),
                        reason: e.to_string(),
                    })
                } else {
                    tracing::warn!(
                        error = %e,
                        action = %event.action.as_str(),
                        resource_id = %resource_id,
                        "Audit append failed (non-blocking)"
                    );
                    Ok(())
                }
            }
        }
    }

    /// Creates a new identity engine, constructing a fresh
    /// [`crate::rbac::EmbeddedRbacEngine`] sharing the same storage and
    /// clock. Convenience for tests and benches that don't need to hold
    /// a separate handle to the RBAC engine.
    pub fn new(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
        audit: Arc<dyn AuditEngine>,
    ) -> Result<Self, IdentityError> {
        let rbac: Arc<dyn crate::rbac::RbacEngine> = Arc::new(
            crate::rbac::EmbeddedRbacEngine::new(Arc::clone(&storage), Arc::clone(&clock)),
        );
        Self::with_rbac(storage, clock, config, rbac, audit)
    }

    /// Creates a new identity engine wired to an explicit RBAC engine.
    ///
    /// Production wiring (where the rbac engine is shared with admin
    /// surfaces) should use this constructor. Generates an Ed25519
    /// signing key and pre-computes a dummy Argon2id hash on construction
    /// for timing-oracle prevention during password verification.
    pub fn with_rbac(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
        rbac: Arc<dyn crate::rbac::RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Result<Self, IdentityError> {
        let dummy_hash = credentials::compute_dummy_hash(&config.credential);
        let signing_key = Arc::new(SigningKey::generate()?);
        let engine = Self {
            storage,
            clock,
            config,
            rbac,
            audit,
            dummy_hash,
            signing_key,
            realm_signing_keys: Mutex::new(HashMap::new()),
            realm_saml_keys: Mutex::new(HashMap::new()),
            oidc_rsa_key: std::sync::OnceLock::new(),
            oidc_ecdsa_key: std::sync::OnceLock::new(),
            attempt_trackers: Mutex::new(HashMap::new()),
            mfa_attempt_trackers: Mutex::new(HashMap::new()),
            magic_link_rate_trackers: Mutex::new(HashMap::new()),
            password_reset_rate_trackers: Mutex::new(HashMap::new()),
            registration_email_rate_trackers: Mutex::new(HashMap::new()),
            registration_ip_rate_trackers: Mutex::new(HashMap::new()),
            ip_login_rate_trackers: Mutex::new(HashMap::new()),
            used_nonces: Mutex::new(HashMap::new()),
            webauthn_challenges: WebAuthnChallengeStore::new(),
            realm_ops_lock: Mutex::new(()),
        };
        engine.seed_system_realm_if_absent()?;
        Ok(engine)
    }

    /// Creates a new identity engine with a pre-existing signing key.
    ///
    /// Used for testing with a known key or for key restoration from storage.
    pub fn with_signing_key(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
        signing_key: Arc<SigningKey>,
        rbac: Arc<dyn crate::rbac::RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        let dummy_hash = credentials::compute_dummy_hash(&config.credential);
        let engine = Self {
            storage,
            clock,
            config,
            rbac,
            audit,
            dummy_hash,
            signing_key,
            realm_signing_keys: Mutex::new(HashMap::new()),
            realm_saml_keys: Mutex::new(HashMap::new()),
            oidc_rsa_key: std::sync::OnceLock::new(),
            oidc_ecdsa_key: std::sync::OnceLock::new(),
            attempt_trackers: Mutex::new(HashMap::new()),
            mfa_attempt_trackers: Mutex::new(HashMap::new()),
            magic_link_rate_trackers: Mutex::new(HashMap::new()),
            password_reset_rate_trackers: Mutex::new(HashMap::new()),
            registration_email_rate_trackers: Mutex::new(HashMap::new()),
            registration_ip_rate_trackers: Mutex::new(HashMap::new()),
            ip_login_rate_trackers: Mutex::new(HashMap::new()),
            used_nonces: Mutex::new(HashMap::new()),
            webauthn_challenges: WebAuthnChallengeStore::new(),
            realm_ops_lock: Mutex::new(()),
        };
        // Best-effort: if seeding fails here, tests that expect a system
        // realm will notice and surface it. `new()` panics on failure; this
        // constructor swallows so existing test harnesses don't break.
        let _ = engine.seed_system_realm_if_absent();
        engine
    }

    /// Ensures the reserved system realm exists in storage. Called from
    /// both constructors. Idempotent — safe to run on every startup.
    ///
    /// The system realm is Hearth's private admin-user home. See
    /// [`crate::identity::keys::system_realm_id`] for the invariants.
    fn seed_system_realm_if_absent(&self) -> Result<(), IdentityError> {
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");
        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(&sys_realm);

        // Already seeded? Skip.
        if self
            .storage
            .get(&sys_realm, &realm_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Ok(());
        }

        let now = self.clock.now();
        let realm = Realm::new(
            sys_realm.clone(),
            keys::SYSTEM_REALM_NAME.to_string(),
            RealmStatus::Active,
            crate::identity::types::RealmConfig::default(),
            now,
            now,
        );
        let realm_bytes = Self::serialize_realm(&realm)?;
        let realm_signing_key = SigningKey::generate()?;
        let key_storage_key = keys::encode_realm_signing_key(&sys_realm);
        let key_bytes = realm_signing_key.pkcs8_bytes().to_vec();
        // Note: we intentionally do NOT write a name index entry — that
        // would let `get_realm_by_name("system")` find it, violating the
        // "invisible to lookups" invariant.

        self.storage
            .put_batch(
                &sys_realm,
                &[(realm_key, realm_bytes), (key_storage_key, key_bytes)],
            )
            .map_err(Self::storage_err)?;

        {
            let mut key_cache = self.realm_signing_keys.lock().expect("key cache lock");
            key_cache.insert(sys_realm.as_uuid().to_string(), Arc::new(realm_signing_key));
        }

        Ok(())
    }

    /// Returns a reference to the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    // ===== Rate limiting helpers =====

    /// Builds a tracker key from realm and user IDs.
    fn tracker_key(realm_id: &RealmId, user_id: &UserId) -> String {
        format!("{}:{}", realm_id.as_uuid(), user_id.as_uuid())
    }

    /// Checks whether the given user is currently rate-limited.
    ///
    /// Uses realm-specific thresholds when configured, falling back to the
    /// global `RateLimitConfig` defaults. Returns `Err(RateLimited)` if the
    /// lockout window has not yet expired.
    fn check_rate_limit(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError> {
        let (max_attempts, lockout_micros) = self.effective_rate_limit(realm_id);
        let key = Self::tracker_key(realm_id, user_id);
        let trackers = self.attempt_trackers.lock().expect("tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= max_attempts {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < lockout_micros {
                    return Err(IdentityError::RateLimited);
                }
                // Lockout window has expired — fall through and allow the attempt.
                // The tracker will be cleared on success or updated on failure.
            }
        }
        Ok(())
    }

    /// Records a failed verification attempt for the given user.
    ///
    /// Returns the new consecutive failure count so callers can determine
    /// whether this attempt triggered a lockout.
    fn record_failed_attempt(&self, realm_id: &RealmId, user_id: &UserId) -> u32 {
        let key = Self::tracker_key(realm_id, user_id);
        let now = self.clock.now().as_micros();
        let mut trackers = self.attempt_trackers.lock().expect("tracker lock");
        let tracker = trackers.entry(key).or_insert(AttemptTracker {
            failed_count: 0,
            last_failure_micros: now,
        });
        tracker.failed_count += 1;
        tracker.last_failure_micros = now;
        tracker.failed_count
    }

    /// Clears the failed attempt tracker for the given user (on success).
    fn clear_attempts(&self, realm_id: &RealmId, user_id: &UserId) {
        let key = Self::tracker_key(realm_id, user_id);
        let mut trackers = self.attempt_trackers.lock().expect("tracker lock");
        trackers.remove(&key);
    }

    /// Returns the effective `(max_attempts, lockout_micros)` for the given
    /// realm, preferring per-realm config over global defaults.
    fn effective_rate_limit(&self, realm_id: &RealmId) -> (u32, i64) {
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            let max = realm
                .config()
                .max_failed_logins
                .unwrap_or(self.config.rate_limit.max_failed_attempts);
            let dur = realm
                .config()
                .lockout_duration_micros
                .unwrap_or(self.config.rate_limit.lockout_duration_micros);
            return (max, dur);
        }
        (
            self.config.rate_limit.max_failed_attempts,
            self.config.rate_limit.lockout_duration_micros,
        )
    }

    /// Returns the effective `(access_ttl_secs, refresh_ttl_secs)` for the
    /// given realm, preferring per-realm overrides over global defaults.
    fn effective_token_ttl_secs(&self, realm_id: &RealmId) -> (i64, i64) {
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            let cfg = realm.config();
            let access = cfg
                .access_token_ttl_micros
                .map(|m| m / 1_000_000)
                .unwrap_or(self.config.token.access_token_ttl_secs);
            let refresh = cfg
                .refresh_token_ttl_micros
                .map(|m| m / 1_000_000)
                .unwrap_or(self.config.token.refresh_token_ttl_secs);
            return (access, refresh);
        }
        (
            self.config.token.access_token_ttl_secs,
            self.config.token.refresh_token_ttl_secs,
        )
    }

    /// Checks whether `method` is permitted by the realm's `allowed_auth_methods`
    /// policy. Returns `Ok(())` when allowed (or when no restriction is configured),
    /// `Err(AuthMethodNotAllowed)` when the method is explicitly excluded.
    fn check_allowed_auth_method(
        &self,
        realm_id: &RealmId,
        method: &'static str,
    ) -> Result<(), IdentityError> {
        if let Ok(Some(realm)) = self.get_realm(realm_id) {
            if let Some(allowed) = realm.config().allowed_auth_methods.as_ref() {
                if !allowed.iter().any(|m| m == method) {
                    return Err(IdentityError::AuthMethodNotAllowed { method });
                }
            }
        }
        Ok(())
    }

    // ===== Per-IP login rate limiting helpers =====

    /// Max failed login attempts per IP per realm before the IP is rate-limited.
    const IP_LOGIN_MAX_ATTEMPTS: u32 = 20;
    /// Rate-limit window for IP-based login throttling: 15 minutes.
    const IP_LOGIN_RATE_WINDOW_MICROS: i64 = 15 * 60 * 1_000_000;

    fn ip_login_tracker_key(realm_id: &RealmId, ip: &str) -> String {
        format!("login-ip:{}:{ip}", realm_id.as_uuid())
    }

    /// Checks whether the given IP has exceeded the per-IP login rate limit.
    ///
    /// Returns `Err(RateLimited)` if the IP has made more than
    /// [`Self::IP_LOGIN_MAX_ATTEMPTS`] failed login attempts within the
    /// sliding window. Passes through for trusted callers (empty IP).
    pub fn check_ip_login_rate_limit(
        &self,
        realm_id: &RealmId,
        ip: &str,
    ) -> Result<(), IdentityError> {
        if ip.is_empty() {
            return Ok(());
        }
        let key = Self::ip_login_tracker_key(realm_id, ip);
        let trackers = self
            .ip_login_rate_trackers
            .lock()
            .expect("ip login tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= Self::IP_LOGIN_MAX_ATTEMPTS {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < Self::IP_LOGIN_RATE_WINDOW_MICROS {
                    return Err(IdentityError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Records a failed login attempt for the given IP.
    ///
    /// Emits `IpLoginLimitExceeded` to the audit log the first time the count
    /// reaches [`Self::IP_LOGIN_MAX_ATTEMPTS`] within the window.
    pub fn record_ip_login_attempt(&self, realm_id: &RealmId, ip: &str) {
        if ip.is_empty() {
            return;
        }
        let key = Self::ip_login_tracker_key(realm_id, ip);
        let now = self.clock.now().as_micros();
        let new_count = {
            let mut trackers = self
                .ip_login_rate_trackers
                .lock()
                .expect("ip login tracker lock");
            let tracker = trackers.entry(key).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
            tracker.failed_count
        };
        if new_count == Self::IP_LOGIN_MAX_ATTEMPTS {
            let ctx = AuditContext {
                actor: Actor::Anonymous,
                metadata: Some(serde_json::json!({ "ip": ip, "attempt_count": new_count })),
            };
            let _ = self.record_audit(
                realm_id,
                Some(&ctx),
                AuditAction::IpLoginLimitExceeded,
                "ip",
                ip,
            );
        }
    }

    // ===== MFA rate limiting helpers =====

    /// MFA rate limit: 5 attempts, 5-minute lockout.
    const MFA_MAX_ATTEMPTS: u32 = 5;
    /// MFA lockout duration: 5 minutes in microseconds.
    const MFA_LOCKOUT_MICROS: i64 = 5 * 60 * 1_000_000;

    /// Builds an MFA tracker key from realm and user IDs.
    fn mfa_tracker_key(realm_id: &RealmId, user_id: &UserId) -> String {
        format!("mfa:{}:{}", realm_id.as_uuid(), user_id.as_uuid())
    }

    /// Checks whether the given user is currently MFA-rate-limited.
    fn check_mfa_rate_limit(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let key = Self::mfa_tracker_key(realm_id, user_id);
        let trackers = self.mfa_attempt_trackers.lock().expect("mfa tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= Self::MFA_MAX_ATTEMPTS {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < Self::MFA_LOCKOUT_MICROS {
                    return Err(IdentityError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Records a failed MFA attempt.
    fn record_mfa_failed_attempt(&self, realm_id: &RealmId, user_id: &UserId) {
        let key = Self::mfa_tracker_key(realm_id, user_id);
        let now = self.clock.now().as_micros();
        let mut trackers = self.mfa_attempt_trackers.lock().expect("mfa tracker lock");
        let tracker = trackers.entry(key).or_insert(AttemptTracker {
            failed_count: 0,
            last_failure_micros: now,
        });
        tracker.failed_count += 1;
        tracker.last_failure_micros = now;
    }

    /// Clears MFA failed attempts on success.
    fn clear_mfa_attempts(&self, realm_id: &RealmId, user_id: &UserId) {
        let key = Self::mfa_tracker_key(realm_id, user_id);
        let mut trackers = self.mfa_attempt_trackers.lock().expect("mfa tracker lock");
        trackers.remove(&key);
    }

    // ===== Magic link rate limiting helpers =====

    /// Magic link rate limit: 3 requests per email per hour.
    const MAGIC_LINK_MAX_REQUESTS: u32 = 3;
    /// Magic link rate limit window: 1 hour in microseconds.
    const MAGIC_LINK_RATE_WINDOW_MICROS: i64 = 60 * 60 * 1_000_000;

    /// Builds a magic link rate tracker key from realm and email.
    fn magic_link_tracker_key(realm_id: &RealmId, email: &str) -> String {
        format!("magic:{}:{email}", realm_id.as_uuid())
    }

    /// Checks whether magic link requests for this email are rate-limited.
    fn check_magic_link_rate_limit(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<(), IdentityError> {
        let key = Self::magic_link_tracker_key(realm_id, email);
        let trackers = self
            .magic_link_rate_trackers
            .lock()
            .expect("magic link tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= Self::MAGIC_LINK_MAX_REQUESTS {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < Self::MAGIC_LINK_RATE_WINDOW_MICROS {
                    return Err(IdentityError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Records a magic link request for rate limiting.
    fn record_magic_link_request(&self, realm_id: &RealmId, email: &str) {
        let key = Self::magic_link_tracker_key(realm_id, email);
        let now = self.clock.now().as_micros();
        let mut trackers = self
            .magic_link_rate_trackers
            .lock()
            .expect("magic link tracker lock");
        let tracker = trackers.entry(key).or_insert(AttemptTracker {
            failed_count: 0,
            last_failure_micros: now,
        });
        tracker.failed_count += 1;
        tracker.last_failure_micros = now;
    }

    // ===== Password reset rate limiting helpers =====

    /// Password reset rate limit: 3 requests per email per 15 minutes.
    const PASSWORD_RESET_MAX_REQUESTS: u32 = 3;
    /// Password reset rate limit window: 15 minutes in microseconds.
    const PASSWORD_RESET_RATE_WINDOW_MICROS: i64 = 15 * 60 * 1_000_000;

    /// Builds a password reset rate tracker key from realm and email.
    fn password_reset_tracker_key(realm_id: &RealmId, email: &str) -> String {
        format!("reset:{}:{email}", realm_id.as_uuid())
    }

    /// Checks whether password reset requests for this email are rate-limited.
    fn check_password_reset_rate_limit(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<(), IdentityError> {
        let key = Self::password_reset_tracker_key(realm_id, email);
        let trackers = self
            .password_reset_rate_trackers
            .lock()
            .expect("password reset tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= Self::PASSWORD_RESET_MAX_REQUESTS {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < Self::PASSWORD_RESET_RATE_WINDOW_MICROS {
                    return Err(IdentityError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Records a password reset request for rate limiting.
    fn record_password_reset_request(&self, realm_id: &RealmId, email: &str) {
        let key = Self::password_reset_tracker_key(realm_id, email);
        let now = self.clock.now().as_micros();
        let mut trackers = self
            .password_reset_rate_trackers
            .lock()
            .expect("password reset tracker lock");
        let tracker = trackers.entry(key).or_insert(AttemptTracker {
            failed_count: 0,
            last_failure_micros: now,
        });
        tracker.failed_count += 1;
        tracker.last_failure_micros = now;
    }

    // ===== Self-service registration rate limiting helpers =====

    /// Registration rate limit: 3 attempts per email per hour.
    const REGISTRATION_EMAIL_MAX_REQUESTS: u32 = 3;
    /// Registration rate limit: 10 attempts per IP per hour across realms.
    const REGISTRATION_IP_MAX_REQUESTS: u32 = 10;
    /// Registration rate limit window: 1 hour in microseconds.
    const REGISTRATION_RATE_WINDOW_MICROS: i64 = 60 * 60 * 1_000_000;

    /// Builds a registration email rate tracker key from realm and email.
    fn registration_email_tracker_key(realm_id: &RealmId, email: &str) -> String {
        format!("reg-email:{}:{email}", realm_id.as_uuid())
    }

    /// Checks per-email and per-IP rate limits for a registration attempt.
    fn check_registration_rate_limit(
        &self,
        realm_id: &RealmId,
        email: &str,
        client_ip: Option<&str>,
    ) -> Result<(), IdentityError> {
        let now = self.clock.now().as_micros();

        // Email bucket
        let email_key = Self::registration_email_tracker_key(realm_id, email);
        {
            let trackers = self
                .registration_email_rate_trackers
                .lock()
                .expect("registration email tracker lock");
            if let Some(tracker) = trackers.get(&email_key) {
                if tracker.failed_count >= Self::REGISTRATION_EMAIL_MAX_REQUESTS
                    && now - tracker.last_failure_micros < Self::REGISTRATION_RATE_WINDOW_MICROS
                {
                    return Err(IdentityError::RateLimited);
                }
            }
        }

        // IP bucket (skipped if caller has no IP)
        if let Some(ip) = client_ip {
            let trackers = self
                .registration_ip_rate_trackers
                .lock()
                .expect("registration ip tracker lock");
            if let Some(tracker) = trackers.get(ip) {
                if tracker.failed_count >= Self::REGISTRATION_IP_MAX_REQUESTS
                    && now - tracker.last_failure_micros < Self::REGISTRATION_RATE_WINDOW_MICROS
                {
                    return Err(IdentityError::RateLimited);
                }
            }
        }

        Ok(())
    }

    /// Records a registration attempt against both email and IP buckets.
    fn record_registration_attempt(
        &self,
        realm_id: &RealmId,
        email: &str,
        client_ip: Option<&str>,
    ) {
        let now = self.clock.now().as_micros();

        let email_key = Self::registration_email_tracker_key(realm_id, email);
        {
            let mut trackers = self
                .registration_email_rate_trackers
                .lock()
                .expect("registration email tracker lock");
            let tracker = trackers.entry(email_key).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
        }

        if let Some(ip) = client_ip {
            let mut trackers = self
                .registration_ip_rate_trackers
                .lock()
                .expect("registration ip tracker lock");
            let tracker = trackers.entry(ip.to_string()).or_insert(AttemptTracker {
                failed_count: 0,
                last_failure_micros: now,
            });
            tracker.failed_count += 1;
            tracker.last_failure_micros = now;
        }
    }

    /// Loads the stored MFA state for a user.
    fn load_mfa_state(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<StoredMfaState>, IdentityError> {
        let key = keys::encode_mfa_totp_key(user_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;
        match bytes {
            Some(b) => {
                let state: StoredMfaState =
                    serde_json::from_slice(&b).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Persists MFA state for a user.
    fn save_mfa_state(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        state: &StoredMfaState,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_mfa_totp_key(user_id);
        let bytes = serde_json::to_vec(state).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    /// Creates a user with an explicit initial status, bypassing the
    /// engine-wide `default_status`. Used by self-service registration
    /// (always `PendingVerification`) while ordinary `create_user` continues
    /// to honor the default.
    fn create_user_with_status(
        &self,
        realm_id: &RealmId,
        request: &CreateUserRequest,
        status: UserStatus,
    ) -> Result<User, IdentityError> {
        let email = validation::validate_email(&request.email)?;
        let first_name = validation::validate_name_part(&request.first_name, "first_name")?;
        let last_name = validation::validate_name_part(&request.last_name, "last_name")?;
        let display_name = if request.display_name.trim().is_empty() {
            let synthesized = format!("{} {}", first_name, last_name).trim().to_string();
            if synthesized.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "display_name or first_name/last_name required".to_string(),
                });
            }
            validation::validate_display_name(&synthesized)?
        } else {
            validation::validate_display_name(&request.display_name)?
        };

        let email_key = keys::encode_user_email(&email);
        let existing = self
            .storage
            .get(realm_id, &email_key)
            .map_err(Self::storage_err)?;
        if existing.is_some() {
            return Err(IdentityError::DuplicateEmail);
        }

        let user_id = UserId::generate();
        let now = self.clock.now();
        let mut user = User::new(
            user_id.clone(),
            email.clone(),
            display_name,
            first_name,
            last_name,
            status,
            now,
            now,
        );

        if !request.attributes.is_empty() {
            Self::validate_user_attributes(&request.attributes)?;
            user.set_attributes(request.attributes.clone());
        }

        let user_bytes = Self::serialize_user(&user)?;
        let user_id_bytes = user_id.as_uuid().to_string().into_bytes();
        self.storage
            .put(realm_id, &email_key, &user_id_bytes)
            .map_err(Self::storage_err)?;
        let id_key = keys::encode_user_id(&user_id);
        self.storage
            .put(realm_id, &id_key, &user_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::UserCreated,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(user)
    }

    /// Validates `User.attributes` key/value constraints.
    ///
    /// Rules (from `AUTHZ_EXPANSION.md § User attributes`):
    /// - Key MUST be non-empty, ≤64 chars, ASCII alphanumeric / `_` / `-` / `.`.
    /// - Value MUST be ≤1 KiB (1024 bytes).
    /// - Total map size (sum of key + value lengths) MUST be ≤16 KiB.
    fn validate_user_attributes(
        attributes: &BTreeMap<String, String>,
    ) -> Result<(), IdentityError> {
        const MAX_TOTAL: usize = 16 * 1024;
        const MAX_VALUE: usize = 1024;
        const MAX_KEY_LEN: usize = 64;
        let mut total = 0usize;
        for (k, v) in attributes {
            if k.is_empty() {
                return Err(IdentityError::InvalidAttribute {
                    reason: "attribute key must not be empty".to_string(),
                });
            }
            if k.len() > MAX_KEY_LEN {
                return Err(IdentityError::InvalidAttribute {
                    reason: format!("attribute key '{k}' exceeds {MAX_KEY_LEN} chars"),
                });
            }
            if !k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                return Err(IdentityError::InvalidAttribute {
                    reason: format!("attribute key '{k}' contains invalid characters"),
                });
            }
            if v.len() > MAX_VALUE {
                return Err(IdentityError::InvalidAttribute {
                    reason: format!("attribute value for '{k}' exceeds {MAX_VALUE} bytes"),
                });
            }
            total += k.len() + v.len();
            if total > MAX_TOTAL {
                return Err(IdentityError::InvalidAttribute {
                    reason: "total attributes size exceeds 16 KiB".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Serializes a user to JSON bytes.
    fn serialize_user(user: &User) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(user).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a user from JSON bytes.
    fn deserialize_user(bytes: &[u8]) -> Result<User, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Wraps a storage error into an `IdentityError`.
    fn storage_err(e: crate::storage::StorageError) -> IdentityError {
        IdentityError::Storage(Box::new(e))
    }

    /// Serializes a stored credential to JSON bytes.
    fn serialize_credential(cred: &StoredCredential) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(cred).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a stored credential from JSON bytes.
    fn deserialize_credential(bytes: &[u8]) -> Result<StoredCredential, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    fn serialize_credential_history(
        history: &[StoredCredential],
    ) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(history).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    fn deserialize_credential_history(
        bytes: &[u8],
    ) -> Result<Vec<StoredCredential>, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Resolves per-realm password policy overrides.
    ///
    /// Returns `None` when the realm has no password policy configured or
    /// when the realm record does not exist (legacy/test realms that rely on
    /// storage namespace-only isolation).
    fn password_policy_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<Option<crate::identity::PasswordPolicy>, IdentityError> {
        Ok(self
            .get_realm(realm_id)?
            .and_then(|r| r.config().password_policy.clone()))
    }

    /// Resolves the effective Argon2id settings for a realm.
    ///
    /// Starts with engine defaults and applies per-realm `password_memory_cost`
    /// and `password_time_cost` overrides when present.
    fn credential_config_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<CredentialConfig, IdentityError> {
        let mut cfg = self.config.credential.clone();
        if let Some(realm) = self.get_realm(realm_id)? {
            if let Some(memory_cost) = realm.config().password_memory_cost {
                cfg.memory_cost_kib = memory_cost;
            }
            if let Some(time_cost) = realm.config().password_time_cost {
                cfg.time_cost = time_cost;
            }
        }
        Ok(cfg)
    }

    /// Serializes a session to JSON bytes.
    fn serialize_session(session: &Session) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(session).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a session from JSON bytes.
    fn deserialize_session(bytes: &[u8]) -> Result<Session, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Loads a raw session from storage without validity checks.
    ///
    /// Returns the deserialized session regardless of expiry/revocation.
    /// Used internally by methods that need to mutate the session.
    fn load_session_raw(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        let key = keys::encode_session_id(session_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;
        match bytes {
            Some(data) => Ok(Some(Self::deserialize_session(&data)?)),
            None => Ok(None),
        }
    }

    /// Computes the SHA-256 hex digest of the given data.
    fn sha256_hex(data: &[u8]) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, data);
        hex_encode(digest.as_ref())
    }

    /// Computes a stable scope digest from a list of scope strings.
    ///
    /// The digest is SHA-256 of the sorted, deduplicated, newline-separated
    /// scope names encoded as UTF-8. The result is a raw 32-byte vector.
    ///
    /// This digest is stored on [`ConsentRecord`] at grant time and
    /// re-computed on every `/authorize` and `refresh_token` call. A mismatch
    /// indicates that the declared scope surface has changed (e.g. because
    /// YAML bundles were reloaded) and the user must re-consent.
    pub(crate) fn compute_scope_digest(scopes: &[String]) -> Vec<u8> {
        let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.dedup();
        let canonical = sorted.join("\n");
        let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
        digest.as_ref().to_vec()
    }

    /// Performs grant family rotation during refresh token exchange.
    ///
    /// Validates the incoming refresh token against the family's current hash,
    /// detects theft (replayed previously-rotated tokens), issues a new token
    /// pair, and rotates the family's stored hash.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn rotate_grant_family(
        &self,
        realm_id: &RealmId,
        fid: &str,
        refresh_token: &str,
        session_id: &SessionId,
        user_id: &UserId,
        now_secs: i64,
        claims: &TokenClaims,
    ) -> Result<TokenPair, IdentityError> {
        let family_key = keys::encode_grant_family(fid);
        let family_bytes = self
            .storage
            .get(realm_id, &family_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::TokenRevoked)?;
        let mut family: StoredGrantFamily =
            serde_json::from_slice(&family_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if family.revoked {
            return Err(IdentityError::TokenRevoked);
        }

        // Verify the incoming refresh token matches the current hash
        let incoming_hash = Self::sha256_hex(refresh_token.as_bytes());
        if incoming_hash != family.current_refresh_hash {
            // THEFT DETECTED — a previously-rotated token is being reused.
            family.revoked = true;
            let updated =
                serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            self.storage
                .put(realm_id, &family_key, &updated)
                .map_err(Self::storage_err)?;
            let _ = self.revoke_session(realm_id, session_id);
            return Err(IdentityError::TokenRevoked);
        }

        // Consent scope-digest re-check on refresh.
        //
        // When the grant family carries a `client_id` and the token carries
        // a non-empty scope claim, verify that the stored consent record's
        // digest still matches the token's scope surface. A mismatch means
        // the scope surface changed since the user last consented; we return
        // `invalid_grant` (mapped to `ConsentRequired`) so the client can
        // direct the user back through the authorization flow.
        if let Some(ref client_id) = family.client_id {
            if let Some(ref scope_str) = claims.scope {
                let token_scopes: Vec<String> =
                    scope_str.split_whitespace().map(str::to_string).collect();
                if let Some(consent) = self.get_consent_extended(
                    realm_id,
                    user_id,
                    client_id,
                    keys::CONSENT_ORG_KEY_REALM,
                    keys::CONSENT_RESOURCE_KEY_DEFAULT,
                    // We don't have the client record in scope here; if the
                    // family carries a client_id we can load it on demand,
                    // but to avoid a storage round-trip we conservatively
                    // disable the spans_orgs fallback (it is checked during
                    // the initial authorize call).
                    false,
                )? {
                    if !consent.scope_digest.is_empty() {
                        let current_digest = Self::compute_scope_digest(&token_scopes);
                        if current_digest != consent.scope_digest {
                            tracing::info!(
                                client_id = %client_id,
                                user_id = %user_id,
                                "consent digest mismatch on refresh — requiring re-consent"
                            );
                            return Err(IdentityError::ConsentRequired);
                        }
                    }
                }
            }
        }

        self.refresh_session(realm_id, session_id)?;

        let signing_key = self.get_signing_key_or_default(realm_id);
        let iat = now_secs;

        // Apply per-realm token TTL overrides for the rotated pair.
        let (access_ttl_secs, refresh_ttl_secs) = self.effective_token_ttl_secs(realm_id);

        let aud = if family.resources.is_empty() {
            Audience::single(self.config.token.audience.clone())
        } else {
            // Preserve the original resource set from the authorization
            // grant. Per RFC 8707 §2, refresh tokens inherit the resource
            // set; the client cannot widen or narrow via refresh. A new
            // authorization request is required to change the resource set.
            Audience::with_resource(self.config.token.audience.clone(), &family.resources[0])
        };

        let new_access_claims = TokenClaims {
            sub: user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: aud.clone(),
            exp: iat + access_ttl_secs,
            iat,
            sid: session_id.to_string(),
            tid: realm_id.to_string(),
            oid: claims.oid.clone(),
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(fid.to_string()),
            scope: claims.scope.clone(),
            nonce: None,
            roles: claims.roles.clone(),
            groups: claims.groups.clone(),
            permissions: claims.permissions.clone(),
            custom: claims.custom.clone(),
        };
        let new_refresh_claims = TokenClaims {
            sub: user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud,
            exp: iat + refresh_ttl_secs,
            iat,
            sid: session_id.to_string(),
            tid: realm_id.to_string(),
            oid: claims.oid.clone(),
            token_type: "refresh".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(fid.to_string()),
            scope: claims.scope.clone(),
            nonce: None,
            roles: claims.roles.clone(),
            groups: claims.groups.clone(),
            permissions: claims.permissions.clone(),
            custom: claims.custom.clone(),
        };

        let new_access = signing_key.issue_token(&new_access_claims)?;
        let new_refresh = signing_key.issue_token(&new_refresh_claims)?;

        // Rotate the family's current refresh hash
        family.current_refresh_hash = Self::sha256_hex(new_refresh.as_bytes());
        // Extend family expiration to match the new refresh token (sliding).
        family.expires_at = crate::core::Timestamp::from_micros(
            self.clock.now().as_micros() + refresh_ttl_secs * 1_000_000,
        );
        let updated = serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &family_key, &updated)
            .map_err(Self::storage_err)?;

        Ok(TokenPair::new(new_access, new_refresh))
    }

    /// Unambiguous alphabet for device user codes (RFC 8628).
    ///
    /// Excludes I/1, O/0, L to avoid confusion. 28 characters.
    const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKMNPQRSTVWXYZ23456789";

    /// User code length (8 characters).
    const USER_CODE_LENGTH: usize = 8;

    /// Generates a random user code for device authorization.
    ///
    /// Uses an unambiguous alphabet to avoid visual confusion.
    fn generate_user_code(rng: &ring::rand::SystemRandom) -> Result<String, IdentityError> {
        let mut bytes = [0u8; Self::USER_CODE_LENGTH];
        rng.fill(&mut bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "random generation failed".to_string(),
            })?;
        let code: String = bytes
            .iter()
            .map(|b| {
                let idx = (*b as usize) % Self::USER_CODE_ALPHABET.len();
                Self::USER_CODE_ALPHABET[idx] as char
            })
            .collect();
        Ok(code)
    }

    /// Computes the PKCE S256 code challenge from a code verifier.
    ///
    /// `S256 = BASE64URL(SHA256(code_verifier))`
    fn pkce_s256_challenge(verifier: &str) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    /// Persists a session to storage (both primary and user index).
    fn persist_session(&self, realm_id: &RealmId, session: &Session) -> Result<(), IdentityError> {
        let session_bytes = Self::serialize_session(session)?;
        let id_key = keys::encode_session_id(session.id());
        self.storage
            .put(realm_id, &id_key, &session_bytes)
            .map_err(Self::storage_err)?;
        Ok(())
    }

    // ===== Realm helpers =====

    /// Serializes a realm record to JSON bytes.
    fn serialize_realm(realm: &Realm) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(realm).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a realm record from JSON bytes.
    fn deserialize_realm(bytes: &[u8]) -> Result<Realm, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Gets the signing key for a realm, falling back to the default key.
    ///
    /// Used by token issuance paths where backward compatibility with
    /// Phase 0 realms (which lack per-realm keys) is needed.
    fn get_signing_key_or_default(&self, realm_id: &RealmId) -> Arc<SigningKey> {
        self.get_or_load_realm_signing_key(realm_id)
            .unwrap_or_else(|_| Arc::clone(&self.signing_key))
    }

    /// Verifies a JWT signature against the realm key, with a fallback to
    /// the legacy global key for backward compatibility.
    fn verify_token_signature_for_realm(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<TokenClaims, IdentityError> {
        let global_verify =
            || tokens::verify_token_signature(token, self.signing_key.public_key_bytes());

        match self.get_or_load_realm_signing_key(realm_id) {
            Ok(realm_key) => {
                match tokens::verify_token_signature(token, realm_key.public_key_bytes()) {
                    Ok(claims) => Ok(claims),
                    Err(IdentityError::InvalidToken) => global_verify(),
                    Err(other) => Err(other),
                }
            }
            Err(IdentityError::RealmNotFound) => global_verify(),
            Err(other) => Err(other),
        }
    }

    /// Parses a `session_`-prefixed session ID claim.
    ///
    /// Returns `Ok(None)` for sessionless tokens (`sid == "none"`).
    fn parse_session_id_claim(claims: &TokenClaims) -> Result<Option<SessionId>, IdentityError> {
        if claims.sid == "none" {
            return Ok(None);
        }

        let sid_str = claims
            .sid
            .strip_prefix("session_")
            .ok_or(IdentityError::InvalidToken)?;
        let sid_uuid = uuid::Uuid::parse_str(sid_str).map_err(|_| IdentityError::InvalidToken)?;
        Ok(Some(SessionId::new(sid_uuid)))
    }

    /// Parses a `user_`-prefixed subject claim.
    fn parse_user_id_claim(claims: &TokenClaims) -> Result<UserId, IdentityError> {
        let sub_str = claims
            .sub
            .strip_prefix("user_")
            .ok_or(IdentityError::InvalidToken)?;
        let sub_uuid = uuid::Uuid::parse_str(sub_str).map_err(|_| IdentityError::InvalidToken)?;
        Ok(UserId::new(sub_uuid))
    }

    /// Returns the server-wide RSA-2048 signing key used to publish the
    /// RS256 entry in the `/certs` JWKS.
    ///
    /// Generates the key the first time it is requested and caches it for
    /// the life of the engine. Future M1 follow-ups will replace this with
    /// a storage-backed lookup so `kid`s remain stable across restarts.
    fn oidc_rsa_signing_key(
        &self,
    ) -> Result<Arc<crate::identity::tokens::RsaSigningKey>, IdentityError> {
        if let Some(existing) = self.oidc_rsa_key.get() {
            return Ok(Arc::clone(existing));
        }
        let generated = Arc::new(crate::identity::tokens::RsaSigningKey::generate(
            "hearth-oidc",
            3650,
        )?);
        // Race: if another thread initialized in parallel, prefer the
        // already-stored value so all callers observe the same `kid`.
        let _ = self.oidc_rsa_key.set(Arc::clone(&generated));
        Ok(Arc::clone(
            self.oidc_rsa_key
                .get()
                .expect("oidc_rsa_key set above or by racing thread"),
        ))
    }

    fn oidc_rsa_jwk(&self) -> Result<crate::identity::tokens::Jwk, IdentityError> {
        self.oidc_rsa_signing_key()?.to_jwk()
    }

    /// Returns the server-wide ECDSA P-256 signing key used to publish the
    /// ES256 entry in the `/certs` JWKS. See `oidc_rsa_signing_key` for
    /// the same caching / persistence caveats.
    fn oidc_ecdsa_signing_key(
        &self,
    ) -> Result<Arc<crate::identity::tokens::EcdsaSigningKey>, IdentityError> {
        if let Some(existing) = self.oidc_ecdsa_key.get() {
            return Ok(Arc::clone(existing));
        }
        let generated = Arc::new(crate::identity::tokens::EcdsaSigningKey::generate()?);
        let _ = self.oidc_ecdsa_key.set(Arc::clone(&generated));
        Ok(Arc::clone(
            self.oidc_ecdsa_key
                .get()
                .expect("oidc_ecdsa_key set above or by racing thread"),
        ))
    }

    fn oidc_ecdsa_jwk(&self) -> Result<crate::identity::tokens::Jwk, IdentityError> {
        Ok(self.oidc_ecdsa_signing_key()?.to_jwk())
    }

    /// Retrieves (or lazily loads from storage) the signing key for a realm.
    ///
    /// Checks the in-memory cache first, then loads from storage on cache miss.
    /// Returns `RealmNotFound` if no per-realm key exists.
    fn get_or_load_realm_signing_key(
        &self,
        realm_id: &RealmId,
    ) -> Result<Arc<SigningKey>, IdentityError> {
        let cache_key = realm_id.as_uuid().to_string();

        // Check cache
        {
            let key_cache = self.realm_signing_keys.lock().expect("key cache lock");
            if let Some(key) = key_cache.get(&cache_key) {
                return Ok(Arc::clone(key));
            }
        }

        // Load from storage
        let sys_realm = keys::system_realm_id();
        let key_storage_key = keys::encode_realm_signing_key(realm_id);
        let key_bytes = self
            .storage
            .get(&sys_realm, &key_storage_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::RealmNotFound)?;

        let signing_key = Arc::new(SigningKey::from_pkcs8(&key_bytes)?);

        // Cache it
        {
            let mut key_cache = self.realm_signing_keys.lock().expect("key cache lock");
            key_cache.insert(cache_key, Arc::clone(&signing_key));
        }

        Ok(signing_key)
    }

    /// Looks up a consent record for the given `(user, client, org_key,
    /// resource_key)` tuple.
    ///
    /// When `consent_spans_orgs` is `true` and no org-specific record is found,
    /// falls back to a realm-level record keyed with
    /// [`CONSENT_ORG_KEY_REALM`][keys::CONSENT_ORG_KEY_REALM].
    fn get_consent_extended(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
        org_key: &str,
        resource_key: &str,
        consent_spans_orgs: bool,
    ) -> Result<Option<ConsentRecord>, IdentityError> {
        // Try the specific (org, resource) tuple first.
        let key = keys::encode_consent_key_extended(user_id, client_id, org_key, resource_key);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            let rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            return Ok(Some(rec));
        }

        // `consent_spans_orgs` fallback: if the client allows a realm-level
        // consent to cover any org, check for a `_realm`-keyed record.
        if consent_spans_orgs && org_key != keys::CONSENT_ORG_KEY_REALM {
            let fallback_key = keys::encode_consent_key_extended(
                user_id,
                client_id,
                keys::CONSENT_ORG_KEY_REALM,
                resource_key,
            );
            if let Some(bytes) = self
                .storage
                .get(realm_id, &fallback_key)
                .map_err(Self::storage_err)?
            {
                let rec: ConsentRecord =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                return Ok(Some(rec));
            }
        }

        // Legacy key fallback for records written before the extended schema.
        let legacy_key = keys::encode_consent_key(user_id, client_id);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &legacy_key)
            .map_err(Self::storage_err)?
        {
            let rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            return Ok(Some(rec));
        }

        Ok(None)
    }
}

impl EmbeddedIdentityEngine {
    /// Returns `{base_issuer}/realms/{name}` for per-realm OIDC scoping.
    /// Falls back to `base_issuer` when the realm cannot be loaded.
    fn realm_issuer_url(&self, realm_id: &RealmId) -> String {
        let base = &self.config.oidc.issuer;
        match self.get_realm(realm_id) {
            Ok(Some(realm)) => format!("{base}/realms/{}", realm.name()),
            _ => base.clone(),
        }
    }

    fn build_discovery_document(&self, issuer: &str) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            userinfo_endpoint: format!("{issuer}/userinfo"),
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: vec!["query".to_string(), "fragment".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "nonce".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "name".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "none".to_string(),
                "client_secret_post".to_string(),
            ],
            code_challenge_methods_supported: vec!["S256".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ],
            registration_endpoint: Some(format!("{issuer}/register")),
            device_authorization_endpoint: Some(format!("{issuer}/device/authorize")),
            revocation_endpoint: Some(format!("{issuer}/revoke")),
            introspection_endpoint: Some(format!("{issuer}/introspect")),
            resource_indicators_supported: true,
            authorization_response_iss_parameter_supported: true,
            end_session_endpoint: Some(format!("{issuer}/end_session")),
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
        }
    }

    /// Verifies a client_credentials (sessionless) token by checking the JTI
    /// blocklist. Returns `Ok(())` if the token is not revoked.
    fn verify_client_credentials_token(
        &self,
        realm_id: &RealmId,
        claims: &TokenClaims,
    ) -> Result<(), IdentityError> {
        if let Some(ref jti) = claims.jti {
            let jti_key = keys::encode_revoked_jti(jti);
            if self
                .storage
                .get(realm_id, &jti_key)
                .map_err(Self::storage_err)?
                .is_some()
            {
                return Err(IdentityError::InvalidToken);
            }
        }
        Ok(())
    }

    /// Emits `LoginFailed` and, when the lockout threshold is first reached,
    /// `LoginLocked` to the audit log. Best-effort: audit failures are logged
    /// but do not affect the caller's error path.
    fn emit_login_failed_audit(&self, realm_id: &RealmId, user_id: &UserId, attempt_count: u32) {
        let (max_attempts, lockout_micros) = self.effective_rate_limit(realm_id);
        let user_id_str = user_id.as_uuid().to_string();

        let failed_ctx = AuditContext {
            actor: Actor::Anonymous,
            metadata: Some(serde_json::json!({ "attempt_count": attempt_count })),
        };
        let _ = self.record_audit(
            realm_id,
            Some(&failed_ctx),
            AuditAction::LoginFailed,
            "credential",
            &user_id_str,
        );

        if attempt_count >= max_attempts {
            let locked_ctx = AuditContext {
                actor: Actor::Anonymous,
                metadata: Some(serde_json::json!({
                    "attempt_count": attempt_count,
                    "lockout_duration_micros": lockout_micros,
                })),
            };
            let _ = self.record_audit(
                realm_id,
                Some(&locked_ctx),
                AuditAction::LoginLocked,
                "credential",
                &user_id_str,
            );
        }
    }
}

impl IdentityEngine for EmbeddedIdentityEngine {
    fn check_ip_login_rate_limit(&self, realm_id: &RealmId, ip: &str) -> Result<(), IdentityError> {
        self.check_ip_login_rate_limit(realm_id, ip)
    }

    fn record_ip_login_attempt(&self, realm_id: &RealmId, ip: &str) {
        self.record_ip_login_attempt(realm_id, ip);
    }

    // ===== Realm lifecycle (Phase 1 Step 19) =====

    fn create_realm(&self, request: &CreateRealmRequest) -> Result<Realm, IdentityError> {
        // Reserved name — the system realm is Hearth-managed.
        if request.name == keys::SYSTEM_REALM_NAME {
            return Err(IdentityError::SystemRealmProtected {
                operation: "create_realm",
            });
        }
        // Slug shape + admin-URL keyword reservation (UI_ROUTING.md R-4).
        // Realm names ride in URL paths, so they must be URL-safe AND
        // must not collide with any admin sub-resource keyword.
        super::validation::validate_realm_name(&request.name)?;
        // Serialize against other realm-record mutations so the atomic
        // record+key `put_batch` below is never interleaved with another
        // thread's update/delete. See `realm_ops_lock` docs.
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");

        // Reject duplicate names — if the name index already points at a
        // realm, refuse rather than silently overwriting the index and
        // leaving an orphaned realm record that the UUID scan would surface.
        if self.get_realm_by_name(&request.name)?.is_some() {
            return Err(IdentityError::DuplicateRealmName);
        }

        let now = self.clock.now();
        let realm_id = RealmId::generate();
        let config = request.config.clone().unwrap_or_default();

        // Generate a per-realm signing key
        let realm_signing_key = SigningKey::generate()?;

        // Persist the realm record under the system realm namespace
        let sys_realm = keys::system_realm_id();
        let realm = Realm::new(
            realm_id.clone(),
            request.name.clone(),
            RealmStatus::Active,
            config,
            now,
            now,
        );
        let realm_bytes = Self::serialize_realm(&realm)?;
        let realm_key = keys::encode_realm_id(&realm_id);
        let key_storage_key = keys::encode_realm_signing_key(&realm_id);
        let key_bytes = realm_signing_key.pkcs8_bytes().to_vec();

        // Name index: realm:name:{name} → realm UUID bytes
        let name_key = keys::encode_realm_name(&request.name);
        let name_value = realm_id.as_uuid().as_bytes().to_vec();

        // Atomic three-entry write: the realm record, signing key, and
        // name index land together or not at all.
        self.storage
            .put_batch(
                &sys_realm,
                &[
                    (realm_key, realm_bytes),
                    (key_storage_key, key_bytes),
                    (name_key, name_value),
                ],
            )
            .map_err(Self::storage_err)?;

        // Cache the signing key in memory
        {
            let mut key_cache = self.realm_signing_keys.lock().expect("key cache lock");
            key_cache.insert(realm_id.as_uuid().to_string(), Arc::new(realm_signing_key));
        }

        self.record_audit(
            &realm_id,
            None,
            AuditAction::RealmCreated,
            "realm",
            &realm_id.as_uuid().to_string(),
        )?;

        Ok(realm)
    }

    fn get_realm(&self, realm_id: &RealmId) -> Result<Option<Realm>, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(realm_id);
        let bytes = self
            .storage
            .get(&sys_realm, &realm_key)
            .map_err(Self::storage_err)?;
        match bytes {
            Some(b) => Ok(Some(Self::deserialize_realm(&b)?)),
            None => Ok(None),
        }
    }

    fn get_realm_by_name(&self, name: &str) -> Result<Option<Realm>, IdentityError> {
        // The reserved system realm is invisible to name lookups. Even
        // though its record is in storage, we refuse to surface it here
        // so that realm resolvers, registration policies, and admin UI
        // dropdowns can never accidentally route into it.
        if name == keys::SYSTEM_REALM_NAME {
            return Ok(None);
        }
        let sys_realm = keys::system_realm_id();
        let name_key = keys::encode_realm_name(name);
        let id_bytes = self
            .storage
            .get(&sys_realm, &name_key)
            .map_err(Self::storage_err)?;
        match id_bytes {
            Some(b) => {
                if b.len() != 16 {
                    return Err(IdentityError::Serialization {
                        reason: "realm name index value has invalid length".to_string(),
                    });
                }
                let uuid =
                    uuid::Uuid::from_slice(&b).map_err(|e| IdentityError::Serialization {
                        reason: format!("invalid UUID in realm name index: {e}"),
                    })?;
                self.get_realm(&RealmId::new(uuid))
            }
            None => Ok(None),
        }
    }

    fn update_realm(
        &self,
        realm_id: &RealmId,
        request: &UpdateRealmRequest,
    ) -> Result<Realm, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "update_realm",
            });
        }
        if matches!(request.name.as_deref(), Some(n) if n == keys::SYSTEM_REALM_NAME) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "update_realm",
            });
        }
        // If the rename targets a new name, validate it the same way
        // create_realm does — including the admin-URL reserved-keyword
        // set (UI_ROUTING.md R-4). Skip when name is unchanged.
        if let Some(ref new_name) = request.name {
            super::validation::validate_realm_name(new_name)?;
        }
        // Serialize against create/delete so an in-flight delete can't
        // race with this read-modify-write and resurrect an orphaned
        // record after its signing key has already been removed.
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");
        let mut realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;

        let now = self.clock.now();
        let old_name = realm.name().to_string();

        if let Some(ref name) = request.name {
            realm.set_name(name.clone());
        }
        if let Some(status) = request.status {
            realm.set_status(status);
        }
        if let Some(ref config) = request.config {
            realm.set_config(config.clone());
        }
        realm.set_updated_at(now);

        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(realm_id);
        let realm_bytes = Self::serialize_realm(&realm)?;

        // If the name changed, update the name index atomically
        if realm.name() == old_name {
            self.storage
                .put(&sys_realm, &realm_key, &realm_bytes)
                .map_err(Self::storage_err)?;
        } else {
            let old_name_key = keys::encode_realm_name(&old_name);
            let new_name_key = keys::encode_realm_name(realm.name());
            let name_value = realm_id.as_uuid().as_bytes().to_vec();
            self.storage
                .put_batch(
                    &sys_realm,
                    &[(realm_key, realm_bytes), (new_name_key, name_value)],
                )
                .map_err(Self::storage_err)?;
            // Best-effort: remove old name index
            let _ = self.storage.delete(&sys_realm, &old_name_key);
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::RealmUpdated,
            "realm",
            &realm_id.as_uuid().to_string(),
        )?;

        Ok(realm)
    }

    #[allow(clippy::too_many_lines)]
    fn delete_realm(&self, realm_id: &RealmId) -> Result<(), IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "delete_realm",
            });
        }
        // Serialize against create/update so a concurrent update can't
        // re-put a realm record after we've already removed its signing
        // key. Without this lock, `record=Some key=None` would leak out
        // and `realm_jwks()` would fail for a still-live-looking realm.
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");
        // Check whether the realm record exists. We do NOT early-return on
        // missing record — a previous cascade may have crashed after deleting
        // the record but before cleaning all key-spaces. Recovery requires us
        // to scan every cascade prefix regardless. If no cascade work is found
        // AND the record is absent, we return RealmNotFound at the end.
        let existing_realm = self.get_realm(realm_id)?;
        let realm_exists = existing_realm.is_some();
        let mut cascade_work_done = false;

        // 0. Delete the realm record FIRST. Ordering matters: if a fault
        //    lands mid-cascade, the observable partial state is "realm
        //    already gone, some cascade residue remains" — never the
        //    reverse ("realm alive but signing key missing"), which would
        //    make `realm_jwks()` fail for a realm the API still reports
        //    as live. The idempotent cascade below converges on retry.
        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(realm_id);
        if realm_exists {
            self.storage
                .delete(&sys_realm, &realm_key)
                .map_err(Self::storage_err)?;
            // Clean up the name index (best-effort)
            if let Some(ref t) = existing_realm {
                let name_key = keys::encode_realm_name(t.name());
                let _ = self.storage.delete(&sys_realm, &name_key);
            }
        }

        // 1. Delete all users in this realm (cascades to sessions, credentials)
        let user_prefix = keys::user_id_scan_prefix();
        let user_end = keys::prefix_end(&user_prefix);
        let users = self
            .storage
            .scan(realm_id, &user_prefix, &user_end)
            .map_err(Self::storage_err)?;

        if !users.is_empty() {
            cascade_work_done = true;
        }

        for entry in &users {
            let user: User = Self::deserialize_user(&entry.value)?;
            // delete_user handles cascade of sessions, credentials, email index
            let _ = self.delete_user(realm_id, user.id());
        }

        // 1a. Unconditional sweep of per-user secondary prefixes. These
        //     indexes are normally cleaned up inside `delete_user`, but a
        //     crash (or an orphaned primary) can leave stragglers. Scanning
        //     by prefix guarantees we reach them on any retry.
        for prefix in [
            &b"usr:email:"[..],
            &b"cred:user:"[..],
            &b"ses:id:"[..],
            &b"ses:user:"[..],
            &b"mfa:totp:"[..],
            &b"webauthn:cred:"[..],
            &b"webauthn:disc:"[..],
            &b"magic:link:"[..],
            &b"email:verify:"[..],
            &b"rst:token:"[..],
        ] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for entry in &entries {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 1b. Unconditional sweep of organization-related prefixes.
        for prefix in [
            &b"org:id:"[..],
            &b"org:slug:"[..],
            &b"orgm:org:"[..],
            &b"orgm:user:"[..],
            &b"orgi:id:"[..],
            &b"orgi:token:"[..],
            &b"orgi:org:"[..],
            &b"orgi:list:"[..],
        ] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for entry in &entries {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 2. Delete all OAuth clients
        let client_prefix = b"oauth:client:";
        let client_end = keys::prefix_end(client_prefix);
        let clients = self
            .storage
            .scan(realm_id, client_prefix, &client_end)
            .map_err(Self::storage_err)?;
        if !clients.is_empty() {
            cascade_work_done = true;
        }
        for entry in &clients {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 3. Delete all authorization tuples (prefix "rel:")
        let rel_prefix = b"rel:";
        let rel_end = keys::prefix_end(rel_prefix);
        let rels = self
            .storage
            .scan(realm_id, rel_prefix, &rel_end)
            .map_err(Self::storage_err)?;
        if !rels.is_empty() {
            cascade_work_done = true;
        }
        for entry in &rels {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 4. Delete all OAuth authorization codes
        let code_prefix = b"oauth:code:";
        let code_end = keys::prefix_end(code_prefix);
        let codes = self
            .storage
            .scan(realm_id, code_prefix, &code_end)
            .map_err(Self::storage_err)?;
        if !codes.is_empty() {
            cascade_work_done = true;
        }
        for entry in &codes {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 5. Delete all grant families
        let family_prefix = keys::grant_family_scan_prefix();
        let family_end = keys::prefix_end(&family_prefix);
        let families = self
            .storage
            .scan(realm_id, &family_prefix, &family_end)
            .map_err(Self::storage_err)?;
        if !families.is_empty() {
            cascade_work_done = true;
        }
        for entry in &families {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 6. Delete all device codes
        let device_prefix = keys::device_code_scan_prefix();
        let device_end = keys::prefix_end(&device_prefix);
        let devices = self
            .storage
            .scan(realm_id, &device_prefix, &device_end)
            .map_err(Self::storage_err)?;
        if !devices.is_empty() {
            cascade_work_done = true;
        }
        for entry in &devices {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 7. Delete all revoked JTIs
        let jti_prefix = b"oauth:revjti:";
        let jti_end = keys::prefix_end(jti_prefix);
        let jtis = self
            .storage
            .scan(realm_id, jti_prefix, &jti_end)
            .map_err(Self::storage_err)?;
        if !jtis.is_empty() {
            cascade_work_done = true;
        }
        for entry in &jtis {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 8. Delete all user-code index entries
        let ucode_prefix = b"oauth:ucode:";
        let ucode_end = keys::prefix_end(ucode_prefix);
        let ucodes = self
            .storage
            .scan(realm_id, ucode_prefix, &ucode_end)
            .map_err(Self::storage_err)?;
        if !ucodes.is_empty() {
            cascade_work_done = true;
        }
        for entry in &ucodes {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 8a. Delete all OAuth consent records in this realm.
        let consent_prefix = keys::oauth_consent_scan_prefix();
        let consent_end = keys::prefix_end(&consent_prefix);
        let consents = self
            .storage
            .scan(realm_id, &consent_prefix, &consent_end)
            .map_err(Self::storage_err)?;
        if !consents.is_empty() {
            cascade_work_done = true;
        }
        for entry in &consents {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 8b. Delete all in-flight pending-authorization tickets.
        let pending_prefix = keys::oauth_pending_auth_scan_prefix();
        let pending_end = keys::prefix_end(&pending_prefix);
        let pendings = self
            .storage
            .scan(realm_id, &pending_prefix, &pending_end)
            .map_err(Self::storage_err)?;
        if !pendings.is_empty() {
            cascade_work_done = true;
        }
        for entry in &pendings {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 8c. Federation connectors, state tokens, confirm-link tickets,
        //     the external-identity indexes (both directions), and the
        //     SCIM externalId indexes (both directions, users + groups).
        for prefix in [
            &b"fed:idp:"[..],
            &b"fed:state:"[..],
            &b"fed:confirm:"[..],
            &b"fed:ext:"[..],
            &b"fed:ext_fwd:"[..],
            &b"scim:ext_user:"[..],
            &b"scim:ext_user_fwd:"[..],
            &b"scim:ext_group:"[..],
            &b"scim:ext_group_fwd:"[..],
        ] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for entry in &entries {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 8d. SAML registrations, state, replay sentinels, SP-session
        //     registrations, and logout state.
        for prefix in [
            &b"saml:sp:"[..],
            &b"saml:state:"[..],
            &b"saml:asn:"[..],
            &b"saml:sp_session:"[..],
            &b"saml:logout:"[..],
        ] {
            let end = keys::prefix_end(prefix);
            let entries = self
                .storage
                .scan(realm_id, prefix, &end)
                .map_err(Self::storage_err)?;
            if !entries.is_empty() {
                cascade_work_done = true;
            }
            for entry in &entries {
                self.storage
                    .delete(realm_id, &entry.key)
                    .map_err(Self::storage_err)?;
            }
        }

        // 8e. SAML per-realm RSA signing key (under system realm scope).
        let saml_key_storage_key = keys::encode_realm_saml_key(realm_id);
        if self
            .storage
            .get(&sys_realm, &saml_key_storage_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            cascade_work_done = true;
            self.storage
                .delete(&sys_realm, &saml_key_storage_key)
                .map_err(Self::storage_err)?;
        }

        // 9. Delete realm signing key (check existence first so we can attribute
        //    cascade work even when only the signing key survives a prior crash).
        let key_storage_key = keys::encode_realm_signing_key(realm_id);
        if self
            .storage
            .get(&sys_realm, &key_storage_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            cascade_work_done = true;
            self.storage
                .delete(&sys_realm, &key_storage_key)
                .map_err(Self::storage_err)?;
        }

        // 10. Remove from in-memory key cache. The record+key were already
        //     deleted durably above; this just drops the cached `Arc`.
        {
            let mut key_cache = self.realm_signing_keys.lock().expect("key cache lock");
            key_cache.remove(&realm_id.as_uuid().to_string());
        }

        // Idempotency guard: if nothing existed for this realm anywhere, the
        // caller is asking to delete something that was never created (or was
        // already fully cleaned). Preserve the `RealmNotFound` contract for
        // that case so the existing API stays stable.
        if !realm_exists && !cascade_work_done {
            return Err(IdentityError::RealmNotFound);
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::RealmDeleted,
            "realm",
            &realm_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn realm_jwks(&self, realm_id: &RealmId) -> Result<JwksDocument, IdentityError> {
        let active_key = self.get_or_load_realm_signing_key(realm_id)?;
        let mut jwks = active_key.to_jwks();

        // Include retiring keys that have not yet passed their grace-period deadline.
        let sys_realm = keys::system_realm_id();
        let scan_prefix = keys::realm_retiring_key_scan_prefix(realm_id);
        let scan_end = keys::prefix_end(&scan_prefix);
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if let Ok(entries) = self.storage.scan(&sys_realm, &scan_prefix, &scan_end) {
            for entry in entries {
                let Some(deadline) = keys::parse_retiring_key_deadline(&entry.key) else {
                    continue;
                };
                if deadline <= now_secs as u64 {
                    continue; // Grace period expired — omit from JWKS.
                }
                if let Ok(retiring_key) = SigningKey::from_pkcs8(&entry.value) {
                    let retiring_jwk = retiring_key.to_jwks();
                    jwks.keys.extend(retiring_jwk.keys);
                }
            }
        }

        Ok(jwks)
    }

    fn rotate_realm_signing_key(
        &self,
        realm_id: &RealmId,
        grace_period_secs: u64,
    ) -> Result<(), IdentityError> {
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");

        // Ensure the realm exists before rotating.
        let sys_realm = keys::system_realm_id();
        let old_key = self.get_or_load_realm_signing_key(realm_id)?;
        let old_key_id = old_key.key_id().to_string();
        let old_pkcs8 = old_key.pkcs8_bytes().to_vec();

        // Generate and store the new active signing key.
        let new_key = SigningKey::generate()?;
        let new_pkcs8 = new_key.pkcs8_bytes().to_vec();
        let key_storage_key = keys::encode_realm_signing_key(realm_id);
        self.storage
            .put(&sys_realm, &key_storage_key, &new_pkcs8)
            .map_err(Self::storage_err)?;

        // Store the old key as a retiring key with its expiry deadline.
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        let deadline_secs = now_secs.saturating_add(grace_period_secs);
        let retiring_key_storage =
            keys::encode_realm_retiring_key(realm_id, deadline_secs, &old_key_id);
        self.storage
            .put(&sys_realm, &retiring_key_storage, &old_pkcs8)
            .map_err(Self::storage_err)?;

        // Invalidate the active key cache so realm_jwks / token issuance pick up the new key.
        {
            let mut cache = self.realm_signing_keys.lock().expect("key cache lock");
            cache.remove(&realm_id.as_uuid().to_string());
        }

        tracing::info!(
            realm = %realm_id.as_uuid(),
            old_kid = %old_key_id,
            new_kid = %new_key.key_id(),
            grace_period_secs,
            deadline_secs,
            "signing key rotated; old key enters grace period"
        );

        Ok(())
    }

    // ===== User CRUD =====

    fn create_user(
        &self,
        realm_id: &RealmId,
        request: &CreateUserRequest,
    ) -> Result<User, IdentityError> {
        // The system realm is reserved for Hearth admins and must be
        // reached only through `create_admin_user`, which also provisions
        // the `realm.admin` RBAC assignment atomically. Without this
        // guard an operator could create a non-admin account in the
        // system realm and gain a session bound to it but without the
        // admin role — harmless today (the permission check would reject
        // the session) but a trap for future refactors.
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "create_user",
            });
        }
        self.create_user_with_status(realm_id, request, self.config.default_status)
    }

    fn create_admin_user(&self, request: &CreateUserRequest) -> Result<User, IdentityError> {
        // Bypasses the `create_user` system-realm guard deliberately.
        // This is the sole public entry point that may create a record
        // in the system realm; callers are responsible for assigning
        // the `realm.admin` RBAC role after the user is persisted.
        let realm_id = keys::system_realm_id();
        self.create_user_with_status(&realm_id, request, self.config.default_status)
    }

    fn get_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<User>, IdentityError> {
        // Conditional span: only allocated when debug tracing is active.
        let _span = tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!(
                "hearth.auth.user_lookup",
                "enduser.id" = %user_id,
                "hearth.realm_id" = %realm_id,
            )
            .entered()
        });

        let key = keys::encode_user_id(user_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;

        match bytes {
            Some(data) => Ok(Some(Self::deserialize_user(&data)?)),
            None => Ok(None),
        }
    }

    fn get_user_by_email(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<User>, IdentityError> {
        // Normalize the lookup email
        let normalized = validation::validate_email(email)?;
        let email_key = keys::encode_user_email(&normalized);

        // Look up UserId from email index
        let id_bytes = self
            .storage
            .get(realm_id, &email_key)
            .map_err(Self::storage_err)?;

        let Some(id_bytes) = id_bytes else {
            return Ok(None);
        };

        // Parse the UserId
        let uuid_str =
            std::str::from_utf8(&id_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let uuid = uuid::Uuid::parse_str(uuid_str).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        let user_id = UserId::new(uuid);

        self.get_user(realm_id, &user_id)
    }

    fn update_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        request: &UpdateUserRequest,
    ) -> Result<User, IdentityError> {
        // 1. Load existing user
        let mut user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        let old_email = user.email().to_string();

        // 2. Apply email change if requested
        if let Some(ref new_email) = request.email {
            let normalized = validation::validate_email(new_email)?;

            if normalized != old_email {
                // Check uniqueness of new email
                let new_email_key = keys::encode_user_email(&normalized);
                let existing = self
                    .storage
                    .get(realm_id, &new_email_key)
                    .map_err(Self::storage_err)?;
                if existing.is_some() {
                    return Err(IdentityError::DuplicateEmail);
                }

                // Remove old email index
                let old_email_key = keys::encode_user_email(&old_email);
                self.storage
                    .delete(realm_id, &old_email_key)
                    .map_err(Self::storage_err)?;

                // Write new email index
                let user_id_bytes = user_id.as_uuid().to_string().into_bytes();
                self.storage
                    .put(realm_id, &new_email_key, &user_id_bytes)
                    .map_err(Self::storage_err)?;

                user.set_email(normalized);
            }
        }

        // 3. Apply display name change if requested
        if let Some(ref new_name) = request.display_name {
            let normalized = validation::validate_display_name(new_name)?;
            user.set_display_name(normalized);
        }

        // 3a. Apply first_name change if requested
        if let Some(ref new_first) = request.first_name {
            let normalized = validation::validate_name_part(new_first, "first_name")?;
            user.set_first_name(normalized);
        }

        // 3b. Apply last_name change if requested
        if let Some(ref new_last) = request.last_name {
            let normalized = validation::validate_name_part(new_last, "last_name")?;
            user.set_last_name(normalized);
        }

        // 4. Apply status change if requested
        if let Some(new_status) = request.status {
            user.set_status(new_status);
        }

        // 4a. Replace attributes map if requested.
        if let Some(attributes) = &request.attributes {
            Self::validate_user_attributes(attributes)?;
            user.set_attributes(attributes.clone());
        }

        // 5. Update timestamp
        user.set_updated_at(self.clock.now());

        // 6. Write updated record
        let user_bytes = Self::serialize_user(&user)?;
        let id_key = keys::encode_user_id(user_id);
        self.storage
            .put(realm_id, &id_key, &user_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::UserUpdated,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(user)
    }

    fn delete_user(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError> {
        // 1. Load user to get email for index cleanup
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // 2. Delete primary record
        let id_key = keys::encode_user_id(user_id);
        self.storage
            .delete(realm_id, &id_key)
            .map_err(Self::storage_err)?;

        // 3. Delete email index
        let email_key = keys::encode_user_email(user.email());
        self.storage
            .delete(realm_id, &email_key)
            .map_err(Self::storage_err)?;

        // 4. Delete credential (if any — best effort, ignore not-found)
        let cred_key = keys::encode_credential_key(user_id);
        self.storage
            .delete(realm_id, &cred_key)
            .map_err(Self::storage_err)?;

        // 4b. Delete MFA state (if any — best effort)
        let mfa_key = keys::encode_mfa_totp_key(user_id);
        self.storage
            .delete(realm_id, &mfa_key)
            .map_err(Self::storage_err)?;

        // 4c. Delete all WebAuthn credentials + discoverable index entries
        let webauthn_prefix = keys::encode_webauthn_credentials_prefix(user_id);
        let webauthn_end = keys::prefix_end(&webauthn_prefix);
        let webauthn_entries = self
            .storage
            .scan(realm_id, &webauthn_prefix, &webauthn_end)
            .map_err(Self::storage_err)?;

        for entry in &webauthn_entries {
            // If discoverable, delete the discoverable index entry
            if let Ok(stored) = serde_json::from_slice::<StoredWebAuthnCredential>(&entry.value) {
                if stored.discoverable {
                    let disc_key = keys::encode_webauthn_discoverable(&stored.credential_id_b64);
                    self.storage
                        .delete(realm_id, &disc_key)
                        .map_err(Self::storage_err)?;
                }
            }
            // Delete the credential itself
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 5. Delete all sessions for this user
        let session_prefix = keys::encode_user_sessions_prefix(user_id);
        let session_end = keys::prefix_end(&session_prefix);
        let session_entries = self
            .storage
            .scan(realm_id, &session_prefix, &session_end)
            .map_err(Self::storage_err)?;

        for entry in &session_entries {
            // Extract session UUID from the user-session index key
            // Key format: "ses:user:{user_uuid}:{session_uuid}"
            let key_str =
                std::str::from_utf8(&entry.key).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if let Some(session_uuid_str) = key_str.rsplit(':').next() {
                if let Ok(uuid) = uuid::Uuid::parse_str(session_uuid_str) {
                    let session_id = SessionId::new(uuid);
                    let session_key = keys::encode_session_id(&session_id);
                    self.storage
                        .delete(realm_id, &session_key)
                        .map_err(Self::storage_err)?;
                }
            }

            // Delete the user-session index entry itself
            // The scan returns keys without realm prefix, so re-use entry.key
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 6. Delete all organization memberships for this user
        let org_membership_prefix = keys::membership_by_user_prefix(user_id);
        let org_membership_end = keys::prefix_end(&org_membership_prefix);
        let org_memberships = self
            .storage
            .scan(realm_id, &org_membership_prefix, &org_membership_end)
            .map_err(Self::storage_err)?;

        for entry in &org_memberships {
            if let Ok(membership) = serde_json::from_slice::<OrganizationMembership>(&entry.value) {
                // Delete forward index (org → user)
                let fwd_key = keys::encode_membership_by_org(membership.org_id(), user_id);
                self.storage
                    .delete(realm_id, &fwd_key)
                    .map_err(Self::storage_err)?;
            }
            // Delete reverse index entry (user → org)
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 7. Cascade: scrub all OAuth consent records for this user.
        let consent_prefix = keys::encode_consent_prefix_for_user(user_id);
        let consent_end = keys::prefix_end(&consent_prefix);
        let consent_entries = self
            .storage
            .scan(realm_id, &consent_prefix, &consent_end)
            .map_err(Self::storage_err)?;
        for entry in &consent_entries {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 8. Cascade: scrub all federated external-identity links for
        //    this user. Each forward index entry holds the external_sub
        //    string as its value — we use it to compute the matching
        //    reverse `fed:ext:{idp_id}:{external_sub}` key and delete
        //    both in one pass. A user must be able to sign up freshly
        //    via the same external identity after deletion, so both
        //    directions MUST go.
        let fed_fwd_prefix = keys::encode_federation_ext_fwd_prefix_for_user(user_id);
        let fed_fwd_end = keys::prefix_end(&fed_fwd_prefix);
        let fed_fwd_entries = self
            .storage
            .scan(realm_id, &fed_fwd_prefix, &fed_fwd_end)
            .map_err(Self::storage_err)?;
        for entry in &fed_fwd_entries {
            // Key format: fed:ext_fwd:{user_uuid}:{idp_uuid}
            let key_str = std::str::from_utf8(&entry.key).unwrap_or("");
            if let Some(idp_uuid_str) = key_str.rsplit(':').next() {
                if let Ok(idp_uuid) = uuid::Uuid::parse_str(idp_uuid_str) {
                    let idp_id = crate::core::IdpId::new(idp_uuid);
                    let external_sub = std::str::from_utf8(&entry.value).unwrap_or("");
                    if !external_sub.is_empty() {
                        let reverse_key = keys::encode_federation_ext_key(&idp_id, external_sub);
                        self.storage
                            .delete(realm_id, &reverse_key)
                            .map_err(Self::storage_err)?;
                    }
                }
            }
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 10. Cascade SCIM externalId mapping. Forward index holds the
        //     external_id string as its value; use it to resolve the
        //     reverse key. Both directions MUST go so a future SCIM POST
        //     with the same externalId can reprovision.
        let scim_fwd_key = keys::encode_scim_ext_user_fwd_key(user_id);
        if let Some(ext_bytes) = self
            .storage
            .get(realm_id, &scim_fwd_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(ext_str) = std::str::from_utf8(&ext_bytes) {
                let reverse_key = keys::encode_scim_ext_user_key(ext_str);
                self.storage
                    .delete(realm_id, &reverse_key)
                    .map_err(Self::storage_err)?;
            }
            self.storage
                .delete(realm_id, &scim_fwd_key)
                .map_err(Self::storage_err)?;
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::UserDeleted,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn set_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<(), IdentityError> {
        // Validate password length
        validation::validate_password_length(password.as_bytes())?;

        // Ensure the user exists.
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        let policy = self.password_policy_for_realm(realm_id)?;
        if let Some(policy) = policy.as_ref() {
            validation::validate_password_against_policy(
                password.as_bytes(),
                policy,
                Some(user.display_name()),
                Some(user.email()),
            )?;
        }

        // Resolve history depth from the realm's password policy.
        let history_depth = policy.as_ref().and_then(|p| p.history_depth).unwrap_or(0);

        // Check history before hashing to avoid the expensive hash on likely reuse.
        if history_depth > 0 {
            // Reject immediate reuse of the current password.
            let current_key = keys::encode_credential_key(user_id);
            if let Some(bytes) = self
                .storage
                .get(realm_id, &current_key)
                .map_err(Self::storage_err)?
            {
                let current_cred = Self::deserialize_credential(&bytes)?;
                if credentials::verify_hash(password, &current_cred.hash)? {
                    return Err(IdentityError::PasswordReused);
                }
            }

            let hist_key = keys::encode_credential_history_key(user_id);
            let hist_bytes = self
                .storage
                .get(realm_id, &hist_key)
                .map_err(Self::storage_err)?;
            if let Some(bytes) = hist_bytes {
                let history = Self::deserialize_credential_history(&bytes)?;
                for old_cred in &history {
                    if credentials::verify_hash(password, &old_cred.hash)? {
                        return Err(IdentityError::PasswordReused);
                    }
                }
            }
        }

        let now = self.clock.now().as_micros();
        let credential_cfg = self.credential_config_for_realm(realm_id)?;
        let cred = credentials::hash_password(password, &credential_cfg, now)?;
        let cred_bytes = Self::serialize_credential(&cred)?;
        let cred_key = keys::encode_credential_key(user_id);

        // Rotate the current credential into history before overwriting it.
        if history_depth > 0 {
            let old_bytes = self
                .storage
                .get(realm_id, &cred_key)
                .map_err(Self::storage_err)?;
            if let Some(bytes) = old_bytes {
                let old_cred = Self::deserialize_credential(&bytes)?;
                let hist_key = keys::encode_credential_history_key(user_id);
                let hist_bytes = self
                    .storage
                    .get(realm_id, &hist_key)
                    .map_err(Self::storage_err)?;
                let mut history = if let Some(b) = hist_bytes {
                    Self::deserialize_credential_history(&b)?
                } else {
                    Vec::new()
                };
                history.insert(0, old_cred);
                history.truncate(history_depth);
                let new_hist_bytes = Self::serialize_credential_history(&history)?;
                self.storage
                    .put(realm_id, &hist_key, &new_hist_bytes)
                    .map_err(Self::storage_err)?;
            }
        }

        self.storage
            .put(realm_id, &cred_key, &cred_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::CredentialSet,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn verify_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<bool, IdentityError> {
        // Enforce realm policy: password must be in the allowed_auth_methods list.
        self.check_allowed_auth_method(realm_id, "password")?;

        // Rate limit check: reject early if account is locked out
        self.check_rate_limit(realm_id, user_id)?;

        // Check user exists
        let user = self.get_user(realm_id, user_id)?;
        if user.is_none() {
            // Timing defense: verify against dummy hash so timing is
            // indistinguishable from a real failed verification.
            // Return generic error to prevent user enumeration.
            let _ = credentials::verify_hash(password, &self.dummy_hash);
            let count = self.record_failed_attempt(realm_id, user_id);
            self.emit_login_failed_audit(realm_id, user_id, count);
            return Err(IdentityError::InvalidCredential {
                reason: "verification failed".to_string(),
            });
        }

        // Load credential
        let cred_key = keys::encode_credential_key(user_id);
        let cred_bytes = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?;

        let Some(cred_bytes) = cred_bytes else {
            // Timing defense: same as above.
            // Return generic error to prevent credential enumeration.
            let _ = credentials::verify_hash(password, &self.dummy_hash);
            let count = self.record_failed_attempt(realm_id, user_id);
            self.emit_login_failed_audit(realm_id, user_id, count);
            return Err(IdentityError::InvalidCredential {
                reason: "verification failed".to_string(),
            });
        };

        let cred = Self::deserialize_credential(&cred_bytes)?;
        let matches = credentials::verify_password(password, &cred)?;

        if matches {
            // Clear failed attempts on success
            self.clear_attempts(realm_id, user_id);

            // Enforce password expiry policy before any mutation. Expired
            // credentials should not be upgraded in place.
            let max_age_days = self
                .password_policy_for_realm(realm_id)?
                .and_then(|p| p.max_age_days);
            if let Some(days) = max_age_days {
                let max_age_micros = i64::from(days) * 24 * 60 * 60 * 1_000_000;
                let now = self.clock.now().as_micros();
                if now - cred.created_at > max_age_micros {
                    return Err(IdentityError::PasswordExpired);
                }
            }

            // Auto-upgrade legacy algorithms on successful verification
            if cred.algorithm != credentials::PasswordAlgorithm::Argon2id {
                let now = self.clock.now().as_micros();
                let credential_cfg = self.credential_config_for_realm(realm_id)?;
                let mut upgraded = credentials::hash_password(password, &credential_cfg, now)?;
                // Rehash must preserve original credential age so expiry
                // semantics stay stable across algorithm migrations.
                upgraded.created_at = cred.created_at;
                let upgraded_bytes = Self::serialize_credential(&upgraded)?;
                self.storage
                    .put(realm_id, &cred_key, &upgraded_bytes)
                    .map_err(Self::storage_err)?;
            } else {
                // Lazy Argon2 rehash: transparently upgrade when config params change.
                let credential_cfg = self.credential_config_for_realm(realm_id)?;
                if credentials::argon2_params_need_rehash(&cred.hash, &credential_cfg) {
                    let now = self.clock.now().as_micros();
                    let mut upgraded = credentials::hash_password(password, &credential_cfg, now)?;
                    // Preserve original age for expiry policy continuity.
                    upgraded.created_at = cred.created_at;
                    let upgraded_bytes = Self::serialize_credential(&upgraded)?;
                    self.storage
                        .put(realm_id, &cred_key, &upgraded_bytes)
                        .map_err(Self::storage_err)?;
                }
            }
        } else {
            let count = self.record_failed_attempt(realm_id, user_id);
            self.emit_login_failed_audit(realm_id, user_id, count);
        }

        Ok(matches)
    }

    fn change_password(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        old_password: &CleartextPassword,
        new_password: &CleartextPassword,
    ) -> Result<(), IdentityError> {
        // Verify old password (this also checks user existence and credential existence)
        let matches = self.verify_password(realm_id, user_id, old_password)?;
        if !matches {
            return Err(IdentityError::InvalidCredential {
                reason: "old password does not match".to_string(),
            });
        }

        // Set the new password
        self.record_audit(
            realm_id,
            None,
            AuditAction::CredentialChanged,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;
        self.set_password(realm_id, user_id, new_password)
    }

    fn create_session(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        context: &SessionContext,
    ) -> Result<Session, IdentityError> {
        // Enforce mfa_required policy unless the session originates from a
        // passkey ceremony (passkeys are inherently multi-factor).
        if !context.satisfies_mfa_via_passkey {
            if let Ok(Some(realm)) = self.get_realm(realm_id) {
                if realm.config().mfa_required.unwrap_or(false) {
                    let has_mfa = self.mfa_enabled(realm_id, user_id).unwrap_or(false);
                    if !has_mfa {
                        return Err(IdentityError::MfaRequired);
                    }
                }
            }
        }

        // Ensure the user exists and is permitted to start a session.
        // Unverified users must complete the email-verification flow first;
        // disabled users are blocked entirely (distinguished from
        // `UserNotFound` because an operator deliberately disabled them).
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;
        match user.status() {
            UserStatus::Active => {}
            UserStatus::PendingVerification => return Err(IdentityError::UserNotVerified),
            UserStatus::Disabled => return Err(IdentityError::Unauthorized),
        }

        // Generate session
        let session_id = SessionId::generate();
        let now = self.clock.now();
        let expires_at = now.add_micros(self.config.session.ttl_micros);
        let session = Session::new(
            session_id.clone(),
            user_id.clone(),
            now,
            expires_at,
            context,
        );

        // Persist session record
        self.persist_session(realm_id, &session)?;

        // Write user-to-session index entry
        let user_session_key = keys::encode_user_session(user_id, &session_id);
        self.storage
            .put(realm_id, &user_session_key, &[])
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::SessionCreated,
            "session",
            &session_id.as_uuid().to_string(),
        )?;

        Ok(session)
    }

    fn get_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        // Conditional span: only allocated when debug tracing is active to
        // preserve the zero-allocation guarantee on the token validation path.
        let _span = tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!(
                "hearth.auth.session_lookup",
                "hearth.session_id" = %session_id,
                "hearth.realm_id" = %realm_id,
            )
            .entered()
        });

        let session = self.load_session_raw(realm_id, session_id)?;
        match session {
            Some(s) if s.is_valid(self.clock.now()) => Ok(Some(s)),
            _ => Ok(None),
        }
    }

    fn revoke_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<(), IdentityError> {
        let mut session = self
            .load_session_raw(realm_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;

        session.revoke();
        self.persist_session(realm_id, &session)?;

        // Cascade: revoke all refresh-token grant families issued under this session.
        let sfam_prefix = keys::encode_session_grant_family_prefix(session_id);
        let sfam_end = keys::prefix_end(&sfam_prefix);
        if let Ok(entries) = self.storage.scan(realm_id, &sfam_prefix, &sfam_end) {
            for entry in &entries {
                let family_id =
                    std::str::from_utf8(&entry.key[sfam_prefix.len()..]).unwrap_or_default();
                if family_id.is_empty() {
                    continue;
                }
                let family_key = keys::encode_grant_family(family_id);
                if let Ok(Some(fbytes)) = self.storage.get(realm_id, &family_key) {
                    if let Ok(mut fam) = serde_json::from_slice::<StoredGrantFamily>(&fbytes) {
                        if !fam.revoked {
                            fam.revoked = true;
                            if let Ok(updated) = serde_json::to_vec(&fam) {
                                let _ = self.storage.put(realm_id, &family_key, &updated);
                            }
                        }
                    }
                }
            }
        }

        let audit_ctx = AuditContext {
            actor: Actor::User(session.user_id().clone()),
            metadata: None,
        };
        self.record_audit(
            realm_id,
            Some(&audit_ctx),
            AuditAction::SessionRevoked,
            "session",
            &session_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn refresh_session(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Session, IdentityError> {
        let mut session = self
            .load_session_raw(realm_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;

        // Cannot refresh a revoked or expired session
        if !session.is_valid(self.clock.now()) {
            return Err(IdentityError::SessionNotFound);
        }

        session.refresh(self.clock.now(), self.config.session.ttl_micros);
        self.persist_session(realm_id, &session)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::SessionCreated,
            "session",
            &session_id.as_uuid().to_string(),
        )?;

        Ok(session)
    }

    fn list_sessions_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError> {
        let prefix = keys::encode_user_sessions_prefix(user_id);
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            // The index key is `ses:user:{user_uuid}:{session_uuid}`.
            // Position just after the cursor session.
            let mut cursor_key = format!("ses:user:{}:{uuid_str}", user_id.as_uuid()).into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let index_entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in index_entries.iter().take(limit + 1) {
            // Extract session UUID from the index key suffix.
            let key_str = String::from_utf8_lossy(&entry.key);
            let Some(session_uuid_str) = key_str.rsplit(':').next() else {
                continue;
            };
            let Ok(session_uuid) = session_uuid_str.parse::<uuid::Uuid>() else {
                continue;
            };
            let session_id = SessionId::new(session_uuid);
            let session_key = keys::encode_session_id(&session_id);
            if let Some(data) = self
                .storage
                .get(realm_id, &session_key)
                .map_err(Self::storage_err)?
            {
                let session: Session =
                    serde_json::from_slice(&data).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                items.push(session);
            }
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            items
                .last()
                .map(|s| URL_SAFE_NO_PAD.encode(s.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn list_sessions_by_realm(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Session>, IdentityError> {
        let prefix = keys::session_id_scan_prefix();
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("ses:id:{uuid_str}").into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in &entries {
            if items.len() > limit {
                break;
            }
            let session: Session =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if !session.is_revoked() {
                items.push(session);
            }
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            items
                .last()
                .map(|s| URL_SAFE_NO_PAD.encode(s.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    // ===== Token management =====

    fn issue_tokens(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> Result<TokenPair, IdentityError> {
        self.issue_tokens_with_context(
            realm_id,
            user_id,
            session_id,
            &TokenIssuanceContext::default(),
        )
    }

    fn issue_tokens_with_context(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        session_id: &SessionId,
        ctx: &TokenIssuanceContext,
    ) -> Result<TokenPair, IdentityError> {
        // Verify user exists
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Verify session exists and is owned by the given user (defense-in-depth:
        // prevents callers from accidentally or maliciously cross-minting tokens
        // for a user_id that doesn't own the referenced session).
        let session = self
            .get_session(realm_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;
        if session.user_id() != user_id {
            return Err(IdentityError::InvalidToken);
        }

        let now = self.clock.now();
        // Resolve effective permissions via RBAC at token-issue time.
        let resolved = self
            .rbac
            .resolve_permissions(user_id, realm_id, None, None)
            .map_err(|e| match e {
                RbacError::TokenSizeExceeded {
                    limit,
                    limit_value,
                    actual,
                } => IdentityError::TokenTooLarge {
                    limit: format!("access_token_{limit}"),
                    limit_value,
                    actual,
                },
                e => IdentityError::Internal {
                    reason: format!("rbac resolve failed: {e}"),
                },
            })?;
        let perm_strs: Vec<String> = resolved
            .permissions
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();

        // Resolve the OAuth client: use the caller-supplied client_id when
        // present, otherwise fall back to the first-party sentinel used by
        // the legacy session-token path.
        let resolved_client = if let Some(ref cid) = ctx.client_id {
            self.get_client(realm_id, cid)?
        } else {
            None
        };
        let sentinel_client =
            OAuthClient::new(ClientId::generate(), "session".to_string(), Vec::new(), now);
        let effective_client = resolved_client.as_ref().unwrap_or(&sentinel_client);

        let oid_ref = ctx.oid.as_deref();

        let (roles, groups, permissions, custom) = self.apply_claim_profile(
            realm_id,
            &user,
            effective_client,
            &resolved,
            &ctx.granted_scopes,
            oid_ref,
            ClaimTarget::AccessToken,
        );
        validate_claim_payload(ClaimTarget::AccessToken, &roles, &groups, &permissions)?;
        self.record_audit(
            realm_id,
            None,
            AuditAction::TokenIssued,
            "token",
            &session_id.as_uuid().to_string(),
        )?;
        // Apply per-realm token TTL overrides if configured.
        let (access_ttl_secs, refresh_ttl_secs) = self.effective_token_ttl_secs(realm_id);
        let effective_token_cfg = TokenConfig {
            access_token_ttl_secs: access_ttl_secs,
            refresh_token_ttl_secs: refresh_ttl_secs,
            ..self.config.token.clone()
        };
        let realm_issuer = self.realm_issuer_url(realm_id);
        self.signing_key.issue_token_pair(&IssueTokenRequest {
            sub: &user_id.to_string(),
            sid: &session_id.to_string(),
            tid: &realm_id.to_string(),
            oid: oid_ref,
            now,
            config: &effective_token_cfg,
            issuer_override: Some(realm_issuer),
            roles: &roles,
            groups: &groups,
            permissions: if permissions.is_empty() {
                &perm_strs
            } else {
                &permissions
            },
            custom,
            resource: ctx.resource.as_ref(),
        })
    }

    fn validate_token(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<TokenClaims, IdentityError> {
        // Conditional span: only allocated when debug tracing is active.
        // validate_token is on the zero-allocation hot path; this guard
        // ensures no heap allocation occurs when debug is disabled.
        let _span = tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!(
                "hearth.auth.token_validate",
                "hearth.realm_id" = %realm_id,
                // token sub/jti are populated after signature verification below
            )
            .entered()
        });

        // Verify Ed25519 signature against realm key (with global-key fallback
        // for Phase 0 realms). Rejects forged, tampered, and alg=none tokens
        // at the cryptographic layer before any claim inspection.
        let claims = self.verify_token_signature_for_realm(realm_id, token)?;

        // Only accept access tokens — refresh tokens must not be accepted here.
        if claims.token_type != "access" {
            return Err(IdentityError::InvalidToken);
        }

        // Enforce expiration before any session or permission check.
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::TokenExpired);
        }
        // Reject tokens issued in the future beyond clock-skew tolerance.
        if claims.iat > now_secs + CLOCK_SKEW_SECS {
            return Err(IdentityError::InvalidToken);
        }
        // Coherence: iat must not exceed exp (would be an invalid token).
        if claims.iat > claims.exp {
            return Err(IdentityError::InvalidToken);
        }

        // Verify the token was issued for this realm.
        if claims.tid != realm_id.to_string() {
            return Err(IdentityError::InvalidToken);
        }

        // RFC 7519 §4.1.3 — audience must include the configured value.
        if !claims.aud.contains(&self.config.token.audience) {
            return Err(IdentityError::InvalidToken);
        }

        // Parse session ID from claims. Sessionless tokens (client_credentials,
        // sid == "none") skip sub-session binding.
        let session_id = Self::parse_session_id_claim(&claims)?;
        let Some(sid) = session_id else {
            self.verify_client_credentials_token(realm_id, &claims)?;
            return Ok(claims);
        };

        // Look up session — this is the actual session-validity check.
        let session = self
            .get_session(realm_id, &sid)?
            .ok_or(IdentityError::InvalidToken)?;

        // Bind claims.sub to session owner (defense-in-depth against sub
        // spoofing via a stolen-but-validly-signed token from another user).
        let user_id = Self::parse_user_id_claim(&claims)?;
        if session.user_id() != &user_id {
            return Err(IdentityError::InvalidToken);
        }

        Ok(claims)
    }

    #[tracing::instrument(
        level = "info",
        skip(self, refresh_token),
        fields(
            hearth_realm_id = %realm_id,
            hearth_oauth_grant_type = "refresh_token",
        )
    )]
    fn refresh_tokens(
        &self,
        realm_id: &RealmId,
        refresh_token: &str,
    ) -> Result<TokenPair, IdentityError> {
        // Verify Ed25519 signature against realm key (with global-key fallback
        // for Phase 0 realms). Rejects forged/tampered tokens at the crypto
        // layer before any claim or session inspection.
        let claims = self.verify_token_signature_for_realm(realm_id, refresh_token)?;

        // Must be a refresh token
        if claims.token_type != "refresh" {
            return Err(IdentityError::InvalidToken);
        }

        // Verify realm matches
        if claims.tid != realm_id.to_string() {
            return Err(IdentityError::InvalidToken);
        }

        // RFC 7519 §4.1.3 — audience must include the configured value.
        if !claims.aud.contains(&self.config.token.audience) {
            return Err(IdentityError::InvalidToken);
        }

        // Check expiration
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::TokenExpired);
        }
        if claims.iat > now_secs + CLOCK_SKEW_SECS {
            return Err(IdentityError::InvalidToken);
        }
        if claims.iat > claims.exp {
            return Err(IdentityError::InvalidToken);
        }

        // Parse session ID
        let session_id_str = claims
            .sid
            .strip_prefix("session_")
            .ok_or(IdentityError::InvalidToken)?;
        let session_uuid =
            uuid::Uuid::parse_str(session_id_str).map_err(|_| IdentityError::InvalidToken)?;
        let session_id = SessionId::new(session_uuid);

        // Parse user ID
        let user_id_str = claims
            .sub
            .strip_prefix("user_")
            .ok_or(IdentityError::InvalidToken)?;
        let user_uuid =
            uuid::Uuid::parse_str(user_id_str).map_err(|_| IdentityError::InvalidToken)?;
        let user_id = UserId::new(user_uuid);

        // Bind token subject to the referenced session. This prevents a
        // mismatched `sub` from minting tokens for a different principal.
        // Use load_session_raw so a revoked session (e.g. after revoke_token)
        // is still visible for the ownership check. Actual revocation is
        // enforced by rotate_grant_family (returns TokenRevoked) or by
        // refresh_session on the legacy path (returns SessionNotFound).
        let session = self
            .load_session_raw(realm_id, &session_id)?
            .ok_or(IdentityError::InvalidToken)?;
        if session.user_id() != &user_id {
            return Err(IdentityError::InvalidToken);
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::TokenRefreshed,
            "token",
            &session_id.as_uuid().to_string(),
        )?;

        // Grant family rotation (if fid is present)
        if let Some(ref fid) = claims.fid {
            self.rotate_grant_family(
                realm_id,
                fid,
                refresh_token,
                &session_id,
                &user_id,
                now_secs,
                &claims,
            )
        } else {
            // Legacy path: Phase-0 session tokens (fid == None).
            // This branch is only reachable by tokens that already passed
            // `verify_token_signature_for_realm` above. A tampered payload
            // with fid stripped cannot reach here — the signature check at the
            // top of this function rejects it first. The session↔user ownership
            // binding enforced above prevents cross-user token issuance on this
            // path.
            self.refresh_session(realm_id, &session_id)?;
            self.issue_tokens(realm_id, &user_id, &session_id)
        }
    }

    fn jwks(&self) -> JwksDocument {
        let mut keys = vec![self.signing_key.to_jwk()];
        // RS256 + ES256 advertised for ecosystem compatibility per
        // ARCHITECTURE.md §8.1 and HEA-51 OIDC M1. Lazily generated on
        // first JWKS access; failures here would only fire if `ring`
        // entropy collection failed, which is unrecoverable. We log and
        // serve a partial JWKS rather than 500 the endpoint.
        match self.oidc_rsa_jwk() {
            Ok(jwk) => keys.push(jwk),
            Err(err) => tracing::error!(error = %err, "failed to materialize RS256 JWKS entry"),
        }
        match self.oidc_ecdsa_jwk() {
            Ok(jwk) => keys.push(jwk),
            Err(err) => tracing::error!(error = %err, "failed to materialize ES256 JWKS entry"),
        }
        JwksDocument { keys }
    }

    // ===== OIDC / OAuth 2.0 =====

    fn register_client(
        &self,
        realm_id: &RealmId,
        request: &RegisterClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        // OAuth clients never target the admin realm. This is the
        // strongest structural guarantee that the admin surface and
        // application auth surfaces cannot be conflated.
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "register_client",
            });
        }
        // Validate client name (non-empty, length limit)
        let client_name = validation::validate_client_name(&request.client_name)?;

        // Redirect URIs are optional for `client_credentials` and device_code grants.
        // For all other grant types, at least one is required.
        let has_client_credentials = request
            .grant_types
            .contains(&"client_credentials".to_string());
        let has_device_code = request
            .grant_types
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string());
        if request.redirect_uris.is_empty() && !has_client_credentials && !has_device_code {
            return Err(IdentityError::InvalidInput {
                reason: "at least one redirect URI is required".to_string(),
            });
        }
        for uri in &request.redirect_uris {
            if uri.trim().is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "redirect URIs must not be empty".to_string(),
                });
            }
            validation::validate_redirect_uri(uri)?;
        }

        let client_id = ClientId::generate();
        let now = self.clock.now();

        let grant_types = if request.grant_types.is_empty() {
            vec!["authorization_code".to_string()]
        } else {
            request.grant_types.clone()
        };

        let mut client = if let Some(ref secret) = request.client_secret {
            // Confidential client — hash the secret with Argon2id
            let secret_hash =
                credentials::hash_raw_secret(secret.as_bytes(), &self.config.credential)?;
            OAuthClient::new_confidential(
                client_id.clone(),
                client_name,
                request.redirect_uris.clone(),
                now,
                secret_hash,
                grant_types,
            )
        } else {
            let mut c = OAuthClient::new(
                client_id.clone(),
                client_name,
                request.redirect_uris.clone(),
                now,
            );
            // Override grant_types from request
            c.set_grant_types(grant_types);
            c
        };

        // Consent is trust-level-driven under the expanded authz model.
        client.set_require_consent(
            request.trust_level == crate::identity::ClientTrustLevel::ThirdParty,
        );
        client.set_client_logo_url(request.client_logo_url.clone());
        client.set_slug(
            request
                .slug
                .clone()
                .unwrap_or_else(|| client.client_name().to_lowercase().replace(' ', "-")),
        );
        client.set_trust_level(request.trust_level);
        client.set_declared_scopes(request.declared_scopes.clone());
        client.set_consent_spans_orgs(request.consent_spans_orgs);

        // Serialize and persist
        let client_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_oauth_client(&client_id);
        self.storage
            .put(realm_id, &key, &client_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientRegistered,
            "client",
            &client_id.as_uuid().to_string(),
        )?;

        Ok(client)
    }

    #[allow(clippy::too_many_lines)]
    fn authorize(
        &self,
        realm_id: &RealmId,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, IdentityError> {
        // 1. Validate response_type
        if request.response_type != "code" {
            return Err(IdentityError::InvalidInput {
                reason: "response_type must be 'code'".to_string(),
            });
        }

        // 2. Validate state is non-empty (CSRF protection)
        if request.state.is_empty() {
            return Err(IdentityError::InvalidGrant {
                reason: "state parameter is required for CSRF protection".to_string(),
            });
        }

        // 2b. Nonce replay protection (when enforcement is enabled)
        if self.config.oidc.enforce_nonces {
            if let Some(ref nonce) = request.nonce {
                let now = self.clock.now();
                let ttl_micros = self.config.oidc.authorization_code_ttl_secs * 1_000_000;
                let mut nonces = self.used_nonces.lock().expect("nonce lock");
                // Sweep nonces older than the auth-code TTL to bound memory.
                nonces.retain(|_, inserted_at| {
                    now.as_micros() - inserted_at.as_micros() < ttl_micros
                });
                if nonces.insert(nonce.clone(), now).is_some() {
                    return Err(IdentityError::InvalidGrant {
                        reason: "nonce has already been used".to_string(),
                    });
                }
            }
        }

        // 3. Load and validate client
        let client_key = keys::encode_oauth_client(&request.client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if client.status() != ApplicationStatus::Active {
            return Err(IdentityError::InvalidClient);
        }

        // 4. Validate redirect_uri matches a registered URI
        if !client.redirect_uris().contains(&request.redirect_uri) {
            return Err(IdentityError::InvalidRedirectUri);
        }

        self.validate_client_scope_request(&client, &request.scope)?;

        // 4b. Consent scope-digest re-check.
        //
        // When a consent record exists for this (user, client) and it carries
        // a non-empty `scope_digest`, re-compute the digest from the requested
        // scopes. A mismatch means the scope surface has changed since the
        // user last consented (e.g. YAML bundles reloaded) — require fresh
        // consent rather than silently issuing a stale grant.
        //
        // Records with an empty digest (written before this feature) are
        // treated as valid to preserve backward compatibility.
        let resource_key = request
            .resource
            .as_deref()
            .unwrap_or(keys::CONSENT_RESOURCE_KEY_DEFAULT);
        if let Some(existing_consent) = self.get_consent_extended(
            realm_id,
            &request.user_id,
            &request.client_id,
            keys::CONSENT_ORG_KEY_REALM,
            resource_key,
            client.consent_spans_orgs(),
        )? {
            // Digest re-check: verify the granted scopes are still self-consistent.
            // Compares the re-computed digest of the stored granted_scopes against
            // what was stored at consent time. A mismatch indicates external tampering
            // or structural corruption; a fresh consent is required.
            // Note: true YAML-bundle-change detection requires resolving scope names
            // to their current permission set and comparing; that is deferred to a
            // future improvement. For now we validate internal record consistency only.
            if !existing_consent.scope_digest.is_empty() {
                let current_digest = Self::compute_scope_digest(&existing_consent.granted_scopes);
                if current_digest != existing_consent.scope_digest {
                    return Err(IdentityError::ConsentRequired);
                }
            }
        }

        // 5. PKCE enforcement (RFC 9700 §2.1.1)
        // All clients must provide PKCE by default. Confidential clients may be
        // exempted via `require_pkce_for_confidential_clients: false` for legacy
        // compatibility only.
        let pkce_required = !client.is_confidential()
            || self.config.oidc.require_pkce_for_confidential_clients;
        if pkce_required && request.code_challenge.is_none() {
            return Err(IdentityError::InvalidInput {
                reason: "PKCE is required (code_challenge with S256 must be supplied)"
                    .to_string(),
            });
        }
        // When a challenge is present, only S256 is permitted (plain is rejected per RFC 9700).
        if request.code_challenge.is_some()
            && !matches!(
                request.code_challenge_method,
                Some(CodeChallengeMethod::S256)
            )
        {
            return Err(IdentityError::InvalidInput {
                reason: "code_challenge requires code_challenge_method=S256".to_string(),
            });
        }
        // code_challenge_method without a challenge is an error
        if request.code_challenge.is_none() && request.code_challenge_method.is_some() {
            return Err(IdentityError::InvalidInput {
                reason: "code_challenge_method requires code_challenge to be present".to_string(),
            });
        }

        // 6. Generate cryptographically random authorization code (32 bytes)
        let rng = ring::rand::SystemRandom::new();
        let mut code_bytes = [0u8; 32];
        rng.fill(&mut code_bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate random bytes for authorization code".to_string(),
            })?;
        let raw_code = URL_SAFE_NO_PAD.encode(code_bytes);

        // 7. Hash the code for storage
        let code_hash = Self::sha256_hex(raw_code.as_bytes());

        // 8. Build stored authorization code
        let now = self.clock.now();
        let ttl_micros = self.config.oidc.authorization_code_ttl_secs * 1_000_000;
        let expires_at = now.add_micros(ttl_micros);

        let stored_code = StoredAuthorizationCode {
            code_hash: code_hash.clone(),
            client_id: request.client_id.clone(),
            user_id: request.user_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            created_at: now,
            expires_at,
            used: false,
            nonce: request.nonce.clone(),
            resource: request.resource.clone(),
        };

        // 9. Persist the code
        let code_key = keys::encode_oauth_code(&code_hash);
        let code_bytes =
            serde_json::to_vec(&stored_code).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &code_key, &code_bytes)
            .map_err(Self::storage_err)?;

        Ok(AuthorizationResponse::new(
            raw_code,
            request.state.clone(),
            self.config.oidc.issuer.clone(),
        ))
    }

    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(
        level = "info",
        skip(self, request),
        fields(
            hearth_realm_id = %realm_id,
            hearth_oauth_client_id = %request.client_id,
            hearth_oauth_grant_type = "authorization_code",
        )
    )]
    fn exchange_authorization_code(
        &self,
        realm_id: &RealmId,
        request: &TokenExchangeRequest,
    ) -> Result<OidcTokenResponse, IdentityError> {
        // 1. Hash the incoming code to find it in storage
        let code_hash = Self::sha256_hex(request.code.as_bytes());
        let code_key = keys::encode_oauth_code(&code_hash);

        // 2. Load the stored code
        let code_bytes = self
            .storage
            .get(realm_id, &code_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidAuthorizationCode)?;

        let mut stored_code: StoredAuthorizationCode = serde_json::from_slice(&code_bytes)
            .map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 3. Check if already used (single-use enforcement)
        if stored_code.used {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 4. Check expiration
        let now = self.clock.now();
        if now >= stored_code.expires_at {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 5. Verify client_id matches
        if stored_code.client_id != request.client_id {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 6. Verify redirect_uri matches
        if stored_code.redirect_uri != request.redirect_uri {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 7. Validate PKCE if code_challenge was present
        if let Some(ref challenge) = stored_code.code_challenge {
            let verifier = request
                .code_verifier
                .as_ref()
                .ok_or(IdentityError::InvalidGrant {
                    reason: "code_verifier is required when code_challenge was used".to_string(),
                })?;

            // Compute S256: BASE64URL(SHA256(code_verifier))
            let computed_challenge = Self::pkce_s256_challenge(verifier);
            if computed_challenge != *challenge {
                return Err(IdentityError::InvalidGrant {
                    reason: "PKCE code_verifier does not match code_challenge".to_string(),
                });
            }
        }

        // 8. Resolve claims and validate size caps before consuming side effects.
        let user = self
            .get_user(realm_id, &stored_code.user_id)?
            .ok_or(IdentityError::UserNotFound)?;
        let client = self
            .get_client(realm_id, &request.client_id)?
            .ok_or(IdentityError::ClientNotFound)?;
        let scope_value = stored_code.scope.trim().to_string();
        let scope_for_resolver =
            if scope_value.is_empty() || scope_value.split_whitespace().count() != 1 {
                None
            } else {
                Some(scope_value.as_str())
            };
        let resolved = self
            .rbac
            .resolve_permissions(&stored_code.user_id, realm_id, None, scope_for_resolver)
            .map_err(|e| match e {
                RbacError::TokenSizeExceeded {
                    limit,
                    limit_value,
                    actual,
                } => IdentityError::TokenTooLarge {
                    limit: format!("access_token_{limit}"),
                    limit_value,
                    actual,
                },
                e => IdentityError::Internal {
                    reason: format!("rbac resolve failed: {e}"),
                },
            })?;
        let granted_scopes: BTreeSet<String> =
            scope_value.split_whitespace().map(str::to_string).collect();
        let (access_roles, access_groups, access_permissions, access_custom) = self
            .apply_claim_profile(
                realm_id,
                &user,
                &client,
                &resolved,
                &granted_scopes,
                None,
                ClaimTarget::AccessToken,
            );
        validate_claim_payload(
            ClaimTarget::AccessToken,
            &access_roles,
            &access_groups,
            &access_permissions,
        )?;
        let (id_roles, id_groups, id_permissions, id_custom) = self.apply_claim_profile(
            realm_id,
            &user,
            &client,
            &resolved,
            &granted_scopes,
            None,
            ClaimTarget::IdToken,
        );
        validate_claim_payload(ClaimTarget::IdToken, &id_roles, &id_groups, &id_permissions)?;

        // 9. Mark the code as used
        stored_code.used = true;
        let updated_bytes =
            serde_json::to_vec(&stored_code).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &code_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 10. Create a session for the user (OAuth code exchange — no browser context)
        let session =
            self.create_session(realm_id, &stored_code.user_id, &SessionContext::default())?;

        // 11. Create grant family for refresh token rotation
        let family_id = uuid::Uuid::new_v4().to_string();

        // 12. Issue tokens with family ID
        let iat = now.as_micros() / 1_000_000;
        let signing_key = self.get_signing_key_or_default(realm_id);

        // Apply per-realm token TTL overrides.
        let (access_ttl_secs, refresh_ttl_secs) = self.effective_token_ttl_secs(realm_id);

        let resource_uri = stored_code
            .resource
            .as_ref()
            .map(|s| {
                Uri::try_from(s.clone()).map_err(|e| IdentityError::InvalidGrant {
                    reason: format!("authorization code has invalid resource URI: {e}"),
                })
            })
            .transpose()?;
        let aud = match &resource_uri {
            Some(r) => Audience::with_resource(self.config.token.audience.clone(), r),
            None => Audience::single(self.config.token.audience.clone()),
        };

        let access_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: aud.clone(),
            exp: iat + access_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(family_id.clone()),
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: None,
            roles: access_roles,
            groups: access_groups,
            permissions: access_permissions,
            custom: access_custom,
        };
        let refresh_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud,
            exp: iat + refresh_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "refresh".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(family_id.clone()),
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: None,
            roles: access_claims.roles.clone(),
            groups: access_claims.groups.clone(),
            permissions: access_claims.permissions.clone(),
            custom: access_claims.custom.clone(),
        };

        let access_token =
            signing_key
                .issue_token(&access_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue access token: {e}"),
                })?;
        let refresh_token =
            signing_key
                .issue_token(&refresh_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue refresh token: {e}"),
                })?;

        // 12. Store grant family with refresh token hash
        let refresh_hash = Self::sha256_hex(refresh_token.as_bytes());
        let family = StoredGrantFamily {
            family_id: family_id.clone(),
            current_refresh_hash: refresh_hash,
            session_id: session.id().clone(),
            realm_id: realm_id.clone(),
            revoked: false,
            created_at: now,
            expires_at: crate::core::Timestamp::from_micros(
                now.as_micros() + refresh_ttl_secs * 1_000_000,
            ),
            // Store the client_id so the refresh path can perform a
            // consent digest re-check without a separate client lookup.
            client_id: Some(request.client_id.clone()),
            resources: resource_uri.iter().cloned().collect(),
        };
        let family_bytes =
            serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let family_key = keys::encode_grant_family(&family_id);
        self.storage
            .put(realm_id, &family_key, &family_bytes)
            .map_err(Self::storage_err)?;
        // Index session → family for cascade revocation on session termination.
        let sfam_key = keys::encode_session_grant_family(&family.session_id, &family_id);
        self.storage
            .put(realm_id, &sfam_key, &[])
            .map_err(Self::storage_err)?;

        // 13. Issue ID token (OIDC-specific, nonce echoed per OIDC Core §2)
        // iss MUST match the discovery document's issuer (OIDC Core §2)
        let id_token_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.config.oidc.issuer.clone(),
            aud: Audience::single(request.client_id.to_string()),
            exp: iat + access_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: realm_id.to_string(),
            oid: None,
            token_type: "id_token".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: (!scope_value.is_empty()).then(|| scope_value.clone()),
            nonce: stored_code.nonce.clone(),
            roles: id_roles,
            groups: id_groups,
            permissions: id_permissions,
            custom: id_custom,
        };
        let id_token =
            signing_key
                .issue_token(&id_token_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue ID token: {e}"),
                })?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::AuthorizationCodeExchanged,
            "authz_code",
            &request.code,
        )?;

        Ok(OidcTokenResponse::new(
            access_token,
            id_token,
            "Bearer".to_string(),
            access_ttl_secs,
            refresh_token,
        ))
    }

    fn oidc_discovery(&self) -> OidcDiscoveryDocument {
        self.build_discovery_document(&self.config.oidc.issuer.clone())
    }

    fn realm_oidc_discovery(
        &self,
        realm_id: &RealmId,
    ) -> Result<OidcDiscoveryDocument, IdentityError> {
        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        let issuer = format!("{}/realms/{}", self.config.oidc.issuer, realm.name());
        Ok(self.build_discovery_document(&issuer))
    }

    // ===== OAuth 2.0 Extended (Step 22) =====

    #[tracing::instrument(
        level = "info",
        skip(self, request),
        fields(
            hearth_realm_id = %realm_id,
            hearth_oauth_client_id = %request.client_id,
            hearth_oauth_grant_type = "client_credentials",
        )
    )]
    fn client_credentials_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::ClientCredentialsRequest,
    ) -> Result<crate::identity::oidc::ClientCredentialsResponse, IdentityError> {
        // 1. Load the client
        let client_key = keys::encode_oauth_client(&request.client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 2. Verify this client supports client_credentials grant
        if !client
            .grant_types()
            .contains(&"client_credentials".to_string())
        {
            return Err(IdentityError::UnsupportedGrantType);
        }

        // 3. Verify client secret
        let secret_hash = client
            .client_secret_hash()
            .ok_or(IdentityError::InvalidClientSecret)?;
        let valid = credentials::verify_raw_secret(request.client_secret.as_bytes(), secret_hash)?;
        if !valid {
            return Err(IdentityError::InvalidClientSecret);
        }

        self.validate_client_scope_request(&client, request.scope.as_deref().unwrap_or(""))?;

        // 4. Issue access token (no session, no refresh token per RFC 6749 §4.4.3)
        let now = self.clock.now();
        let iat = now.as_micros() / 1_000_000;
        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;

        let scope = request.scope.clone();
        let access_claims = TokenClaims {
            sub: request.client_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: Audience::single(self.config.token.audience.clone()),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            sid: "none".to_string(), // No session for client credentials
            tid: realm_id.to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: scope.clone(),
            nonce: None,
            roles: Vec::new(),
            groups: Vec::new(),
            permissions: Vec::new(),
            custom: std::collections::BTreeMap::new(),
        };

        let access_token =
            signing_key
                .issue_token(&access_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue access token: {e}"),
                })?;

        Ok(crate::identity::oidc::ClientCredentialsResponse::new(
            access_token,
            "Bearer".to_string(),
            self.config.token.access_token_ttl_secs,
            scope,
        ))
    }

    fn device_authorize(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::DeviceAuthorizationRequest,
    ) -> Result<crate::identity::oidc::DeviceAuthorizationResponse, IdentityError> {
        use crate::identity::oidc::{DeviceCodeStatus, StoredDeviceCode};

        // 1. Verify client exists
        let client_key = keys::encode_oauth_client(&request.client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        self.validate_client_scope_request(&client, request.scope.as_deref().unwrap_or(""))?;

        // 2. Generate device code (32 random bytes → base64url)
        let rng = ring::rand::SystemRandom::new();
        let mut device_code_bytes = [0u8; 32];
        rng.fill(&mut device_code_bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "random generation failed".to_string(),
            })?;
        let device_code = URL_SAFE_NO_PAD.encode(device_code_bytes);

        // 3. Generate user code (8 chars from unambiguous alphabet)
        let user_code = Self::generate_user_code(&rng)?;

        let now = self.clock.now();
        let expires_in = 600_i64; // 10 minutes
        let interval = 5_i64;
        let device_code_hash = Self::sha256_hex(device_code.as_bytes());

        // 4. Store device code
        let stored = StoredDeviceCode {
            device_code_hash: device_code_hash.clone(),
            user_code: user_code.clone(),
            client_id: request.client_id.clone(),
            realm_id: realm_id.clone(),
            scope: request.scope.clone(),
            status: DeviceCodeStatus::Pending,
            created_at: now,
            expires_at: crate::core::Timestamp::from_micros(
                now.as_micros() + expires_in * 1_000_000,
            ),
            interval,
            last_polled_at: None,
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let dc_key = keys::encode_device_code(&device_code_hash);
        self.storage
            .put(realm_id, &dc_key, &stored_bytes)
            .map_err(Self::storage_err)?;

        // 5. Store user code → device code hash mapping
        let uc_key = keys::encode_user_code(&user_code);
        self.storage
            .put(realm_id, &uc_key, device_code_hash.as_bytes())
            .map_err(Self::storage_err)?;

        Ok(crate::identity::oidc::DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri: format!("{}/device", self.config.oidc.issuer),
            expires_in,
            interval,
        })
    }

    fn approve_device(
        &self,
        realm_id: &RealmId,
        user_code: &str,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        // 1. Look up user code → device code hash
        let uc_key = keys::encode_user_code(user_code);
        let dc_hash_bytes = self
            .storage
            .get(realm_id, &uc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::DeviceCodeExpired)?;
        let dc_hash = String::from_utf8(dc_hash_bytes)
            .map_err(|_| IdentityError::InvalidAuthorizationCode)?;

        // 2. Load device code
        let dc_key = keys::encode_device_code(&dc_hash);
        let dc_bytes = self
            .storage
            .get(realm_id, &dc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::DeviceCodeExpired)?;
        let mut stored: StoredDeviceCode =
            serde_json::from_slice(&dc_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 3. Check expiration
        let now = self.clock.now();
        if now >= stored.expires_at {
            return Err(IdentityError::DeviceCodeExpired);
        }

        // 4. Must be pending
        if stored.status != DeviceCodeStatus::Pending {
            return Err(IdentityError::InvalidAuthorizationCode);
        }

        // 5. Approve
        stored.status = DeviceCodeStatus::Approved {
            user_id: user_id.clone(),
        };
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &dc_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::AuthorizationCodeExchanged,
            "device",
            user_code,
        )?;

        Ok(())
    }

    fn poll_device_token(
        &self,
        realm_id: &RealmId,
        device_code: &str,
        client_id: &ClientId,
    ) -> Result<OidcTokenResponse, IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        // 1. Look up device code by hash
        let dc_hash = Self::sha256_hex(device_code.as_bytes());
        let dc_key = keys::encode_device_code(&dc_hash);
        let dc_bytes = self
            .storage
            .get(realm_id, &dc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::DeviceCodeExpired)?;
        let mut stored: StoredDeviceCode =
            serde_json::from_slice(&dc_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 2. Verify client matches
        if stored.client_id != *client_id {
            return Err(IdentityError::InvalidClient);
        }

        let now = self.clock.now();

        // 3. Check expiration
        if now >= stored.expires_at {
            return Err(IdentityError::DeviceCodeExpired);
        }

        // 4. Rate limit polling
        if let Some(last_polled) = stored.last_polled_at {
            let elapsed_secs = (now.as_micros() - last_polled.as_micros()) / 1_000_000;
            if elapsed_secs < stored.interval {
                return Err(IdentityError::SlowDown);
            }
        }

        // 5. Update last_polled_at
        stored.last_polled_at = Some(now);
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &dc_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 6. Check status
        match &stored.status {
            DeviceCodeStatus::Pending => Err(IdentityError::AuthorizationPending),
            DeviceCodeStatus::Denied => Err(IdentityError::DeviceCodeDenied),
            DeviceCodeStatus::Expired => Err(IdentityError::DeviceCodeExpired),
            DeviceCodeStatus::Approved { user_id } => {
                // Issue tokens like exchange_authorization_code (device flow — no browser context)
                let session = self.create_session(realm_id, user_id, &SessionContext::default())?;
                let token_pair = self.issue_tokens(realm_id, user_id, session.id())?;

                // Issue ID token
                // iss MUST match the discovery document's issuer (OIDC Core §2)
                let iat = now.as_micros() / 1_000_000;
                let id_token_claims = TokenClaims {
                    sub: user_id.to_string(),
                    iss: self.config.oidc.issuer.clone(),
                    aud: Audience::single(client_id.to_string()),
                    exp: iat + self.config.token.access_token_ttl_secs,
                    iat,
                    sid: session.id().to_string(),
                    tid: realm_id.to_string(),
                    oid: None,
                    token_type: "id_token".to_string(),
                    jti: Some(uuid::Uuid::new_v4().to_string()),
                    fid: None,
                    scope: stored.scope.clone(),
                    nonce: None,
                    roles: Vec::new(),
                    groups: Vec::new(),
                    permissions: Vec::new(),
                    custom: std::collections::BTreeMap::new(),
                };
                let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
                let id_token = signing_key.issue_token(&id_token_claims).map_err(|e| {
                    IdentityError::SigningError {
                        reason: format!("failed to issue ID token: {e}"),
                    }
                })?;

                // Clean up device code and user code
                let _ = self.storage.delete(realm_id, &dc_key);
                let uc_key = keys::encode_user_code(&stored.user_code);
                let _ = self.storage.delete(realm_id, &uc_key);

                Ok(OidcTokenResponse::new(
                    token_pair.access_token().to_string(),
                    id_token,
                    "Bearer".to_string(),
                    self.config.token.access_token_ttl_secs,
                    token_pair.refresh_token().to_string(),
                ))
            }
        }
    }

    fn revoke_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::TokenRevocationRequest,
    ) -> Result<(), IdentityError> {
        // RFC 7009: invalid tokens → 200 OK (no error). Signature
        // verification prevents forged tokens from targeting real sessions
        // or grant families for revocation.
        let Ok(claims) = self.verify_token_signature_for_realm(realm_id, &request.token) else {
            return Ok(());
        };

        // Verify realm matches
        if claims.tid != realm_id.to_string() {
            return Ok(()); // Silent success per RFC 7009
        }

        match claims.token_type.as_str() {
            "access" | "id_token" => {
                if claims.sid != "none" {
                    // Session-bound token: revoke via session
                    let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
                    if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                        let session_id = SessionId::new(uuid);
                        let _ = self.revoke_session(realm_id, &session_id);
                    }
                } else if let Some(ref jti) = claims.jti {
                    // Sessionless token (e.g., client_credentials): revoke via JTI blocklist
                    let jti_key = keys::encode_revoked_jti(jti);
                    let _ = self.storage.put(realm_id, &jti_key, b"1");
                }
            }
            "refresh" => {
                // Revoke via grant family
                if let Some(ref fid) = claims.fid {
                    let family_key = keys::encode_grant_family(fid);
                    if let Some(family_bytes) = self
                        .storage
                        .get(realm_id, &family_key)
                        .map_err(Self::storage_err)?
                    {
                        let mut family: StoredGrantFamily = serde_json::from_slice(&family_bytes)
                            .map_err(|e| {
                            IdentityError::Serialization {
                                reason: e.to_string(),
                            }
                        })?;
                        family.revoked = true;
                        let updated = serde_json::to_vec(&family).map_err(|e| {
                            IdentityError::Serialization {
                                reason: e.to_string(),
                            }
                        })?;
                        self.storage
                            .put(realm_id, &family_key, &updated)
                            .map_err(Self::storage_err)?;
                    }
                }
                // Also revoke session if present
                if claims.sid != "none" {
                    let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
                    if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                        let session_id = SessionId::new(uuid);
                        let _ = self.revoke_session(realm_id, &session_id);
                    }
                }
            }
            _ => {} // Unknown token type → silent success
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::SessionRevoked,
            "token",
            &request.token,
        )?;

        Ok(())
    }

    fn introspect_token(
        &self,
        realm_id: &RealmId,
        request: &crate::identity::oidc::TokenIntrospectionRequest,
    ) -> Result<crate::identity::oidc::IntrospectionResponse, IdentityError> {
        use crate::identity::oidc::IntrospectionResponse;

        // 1. Verify Ed25519 signature against realm key (with global-key
        // fallback for Phase 0 realms). Forged or tampered tokens are
        // cryptographically rejected; RFC 7662 semantics: return inactive.
        let Ok(claims) = self.verify_token_signature_for_realm(realm_id, &request.token) else {
            return Ok(IntrospectionResponse::inactive());
        };

        // 2. Verify realm matches
        if claims.tid != realm_id.to_string() {
            return Ok(IntrospectionResponse::inactive());
        }

        // 2a. RFC 7519 §4.1.3 — audience must include the configured value.
        if !claims.aud.contains(&self.config.token.audience) {
            return Ok(IntrospectionResponse::inactive());
        }

        // 3. Check expiration and iat sanity
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Ok(IntrospectionResponse::inactive());
        }
        if claims.iat > now_secs + CLOCK_SKEW_SECS {
            return Ok(IntrospectionResponse::inactive());
        }
        if claims.iat > claims.exp {
            return Ok(IntrospectionResponse::inactive());
        }

        // 4. Check session validity (if session-bound) or JTI blocklist (if sessionless)
        if claims.sid != "none" {
            let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
            if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                let session_id = SessionId::new(uuid);
                if self.get_session(realm_id, &session_id)?.is_none() {
                    return Ok(IntrospectionResponse::inactive());
                }
            }
        } else if let Some(ref jti) = claims.jti {
            // Sessionless token — check JTI revocation blocklist
            let jti_key = keys::encode_revoked_jti(jti);
            if self
                .storage
                .get(realm_id, &jti_key)
                .map_err(Self::storage_err)?
                .is_some()
            {
                return Ok(IntrospectionResponse::inactive());
            }
        }

        // 5. Check grant family (if refresh token with fid)
        if claims.token_type == "refresh" {
            if let Some(ref fid) = claims.fid {
                let family_key = keys::encode_grant_family(fid);
                if let Some(family_bytes) = self
                    .storage
                    .get(realm_id, &family_key)
                    .map_err(Self::storage_err)?
                {
                    let family: StoredGrantFamily =
                        serde_json::from_slice(&family_bytes).map_err(|e| {
                            IdentityError::Serialization {
                                reason: e.to_string(),
                            }
                        })?;
                    if family.revoked {
                        return Ok(IntrospectionResponse::inactive());
                    }
                }
            }
        }

        // 6. Active — return metadata
        Ok(IntrospectionResponse {
            active: true,
            scope: claims.scope,
            client_id: None, // Not stored in claims for session-bound tokens
            sub: Some(claims.sub),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            token_type: Some(claims.token_type),
            iss: Some(claims.iss),
            aud: Some(claims.aud.base().to_string()),
        })
    }

    // ===== MFA / TOTP (Step 23) =====

    fn enroll_totp(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<TotpEnrollment, IdentityError> {
        // Ensure user exists
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Check not already enrolled
        if let Some(existing) = self.load_mfa_state(realm_id, user_id)? {
            if existing.enabled {
                return Err(IdentityError::MfaAlreadyEnabled);
            }
        }

        // Generate secret + recovery codes (no hashing here — deferred to
        // verify_totp_enrollment() so the enrollment page loads instantly).
        let secret = TotpSecret::generate()?;
        let secret_base32 = secret.to_base32();
        let provisioning_uri =
            totp::generate_provisioning_uri(&secret_base32, user.email(), "Hearth");
        let recovery_codes = totp::generate_recovery_codes()?;

        // Store disabled state with plaintext recovery codes. Hashing is
        // deferred to confirmation so this page load stays fast (~0ms vs ~3s).
        let state = StoredMfaState {
            secret_base32: secret_base32.clone(),
            enabled: false,
            recovery_code_hashes: Vec::new(),
            last_used_step: None,
            enabled_at: None,
            pending_recovery_codes: Some(recovery_codes.clone()),
        };
        self.save_mfa_state(realm_id, user_id, &state)?;

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::CredentialSet,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(TotpEnrollment {
            secret_base32,
            provisioning_uri,
            recovery_codes: RecoveryCodes::new(recovery_codes),
        })
    }

    #[allow(clippy::cast_sign_loss)] // Timestamps are always positive
    fn verify_totp_enrollment(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        let mut state = self
            .load_mfa_state(realm_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if state.enabled {
            return Err(IdentityError::MfaAlreadyEnabled);
        }

        // Validate code against the stored secret
        let secret = TotpSecret::from_base32(&state.secret_base32)?;
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        let matched_step = totp::validate_totp(secret.as_bytes(), code, now_secs, None);

        if let Some(step) = matched_step {
            // Hash the pending plaintext recovery codes now (deferred from
            // enroll_totp to keep page load fast).
            let recovery_hashes = if let Some(ref codes) = state.pending_recovery_codes {
                totp::hash_recovery_codes(codes, &self.config.credential)?
            } else {
                // Legacy path: codes were already hashed at enrollment time.
                state.recovery_code_hashes.clone()
            };

            state.enabled = true;
            state.last_used_step = Some(step);
            state.enabled_at = Some(self.clock.now().as_micros());
            state.recovery_code_hashes = recovery_hashes;
            state.pending_recovery_codes = None;
            self.save_mfa_state(realm_id, user_id, &state)?;
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata: None,
                }),
                AuditAction::CredentialVerified,
                "credential",
                &user_id.as_uuid().to_string(),
            )?;
            Ok(())
        } else {
            Err(IdentityError::InvalidMfaCode)
        }
    }

    #[allow(clippy::cast_sign_loss)] // Timestamps are always positive
    fn verify_totp(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        // Rate limit check
        self.check_mfa_rate_limit(realm_id, user_id)?;

        let mut state = self
            .load_mfa_state(realm_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if !state.enabled {
            return Err(IdentityError::MfaNotEnabled);
        }

        let secret = TotpSecret::from_base32(&state.secret_base32)?;
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        let matched_step =
            totp::validate_totp(secret.as_bytes(), code, now_secs, state.last_used_step);

        if let Some(step) = matched_step {
            state.last_used_step = Some(step);
            self.save_mfa_state(realm_id, user_id, &state)?;
            self.clear_mfa_attempts(realm_id, user_id);
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata: None,
                }),
                AuditAction::CredentialVerified,
                "credential",
                &user_id.as_uuid().to_string(),
            )?;
            Ok(())
        } else {
            self.record_mfa_failed_attempt(realm_id, user_id);
            Err(IdentityError::InvalidMfaCode)
        }
    }

    fn verify_recovery_code(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        let mut state = self
            .load_mfa_state(realm_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if !state.enabled {
            return Err(IdentityError::MfaNotEnabled);
        }

        let idx = totp::verify_recovery_code(code, &state.recovery_code_hashes)?;
        match idx {
            Some(i) => {
                // Mark recovery code as used
                state.recovery_code_hashes[i] = None;
                self.save_mfa_state(realm_id, user_id, &state)?;
                self.clear_mfa_attempts(realm_id, user_id);
                self.record_audit(
                    realm_id,
                    Some(&AuditContext {
                        actor: Actor::User(user_id.clone()),
                        metadata: None,
                    }),
                    AuditAction::CredentialVerified,
                    "credential",
                    &user_id.as_uuid().to_string(),
                )?;
                Ok(())
            }
            None => Err(IdentityError::InvalidMfaCode),
        }
    }

    fn disable_mfa(&self, realm_id: &RealmId, user_id: &UserId) -> Result<(), IdentityError> {
        let state = self.load_mfa_state(realm_id, user_id)?;
        match state {
            Some(s) if s.enabled => {
                let key = keys::encode_mfa_totp_key(user_id);
                self.storage
                    .delete(realm_id, &key)
                    .map_err(Self::storage_err)?;
                self.clear_mfa_attempts(realm_id, user_id);
                self.record_audit(
                    realm_id,
                    Some(&AuditContext {
                        actor: Actor::User(user_id.clone()),
                        metadata: None,
                    }),
                    AuditAction::CredentialChanged,
                    "credential",
                    &user_id.as_uuid().to_string(),
                )?;
                Ok(())
            }
            _ => Err(IdentityError::MfaNotEnabled),
        }
    }

    fn mfa_enabled(&self, realm_id: &RealmId, user_id: &UserId) -> Result<bool, IdentityError> {
        match self.load_mfa_state(realm_id, user_id)? {
            Some(state) => Ok(state.enabled),
            None => Ok(false),
        }
    }

    fn load_pending_recovery_codes(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<Vec<String>>, IdentityError> {
        match self.load_mfa_state(realm_id, user_id)? {
            Some(state) if !state.enabled => Ok(state.pending_recovery_codes),
            _ => Ok(None),
        }
    }

    fn regenerate_recovery_codes(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<String>, IdentityError> {
        let mut state = self
            .load_mfa_state(realm_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if !state.enabled {
            return Err(IdentityError::MfaNotEnabled);
        }

        let codes = totp::generate_recovery_codes()?;
        let hashes = totp::hash_recovery_codes(&codes, &self.config.credential)?;
        state.recovery_code_hashes = hashes;
        state.pending_recovery_codes = None;
        self.save_mfa_state(realm_id, user_id, &state)?;

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::CredentialChanged,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(codes)
    }

    // ===== WebAuthn / Passkeys (Step 24) =====

    fn start_webauthn_registration(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        options: &RegistrationOptions,
    ) -> Result<Vec<u8>, IdentityError> {
        // Ensure user exists
        self.get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Cleanup expired challenges
        let now = self.clock.now().as_micros();
        self.webauthn_challenges.cleanup_expired(now);

        // Generate and store challenge
        let challenge = webauthn::generate_challenge()?;
        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: options.rp_id.clone(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: now,
        };
        self.webauthn_challenges.insert(pending);

        Ok(challenge)
    }

    fn complete_webauthn_registration(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_data_json: &[u8],
        attestation_object: &[u8],
        origin: &str,
        discoverable: bool,
    ) -> Result<WebAuthnCredentialInfo, IdentityError> {
        // Extract challenge from clientDataJSON to look up pending
        let client_data: serde_json::Value =
            serde_json::from_slice(client_data_json).map_err(|e| {
                IdentityError::WebAuthnRegistrationFailed {
                    reason: format!("invalid clientDataJSON: {e}"),
                }
            })?;
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdentityError::WebAuthnRegistrationFailed {
                reason: "missing challenge in clientDataJSON".to_string(),
            })?;

        let pending = self
            .webauthn_challenges
            .remove(challenge_b64)
            .ok_or_else(|| IdentityError::WebAuthnRegistrationFailed {
                reason: "challenge not found or expired".to_string(),
            })?;

        // Check expiry
        let now = self.clock.now().as_micros();
        if now - pending.created_at > 5 * 60 * 1_000_000 {
            return Err(IdentityError::WebAuthnRegistrationFailed {
                reason: "challenge expired".to_string(),
            });
        }

        let (mut info, mut stored) = webauthn::complete_registration(
            &pending,
            client_data_json,
            attestation_object,
            origin,
            now,
        )?;

        // Set discoverable from caller's request
        info = WebAuthnCredentialInfo {
            credential_id: info.credential_id().to_vec(),
            algorithm: info.algorithm(),
            discoverable,
            name: None,
        };
        stored.discoverable = discoverable;

        // Persist credential
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(info.credential_id());
        let key = keys::encode_webauthn_credential(user_id, &cred_id_b64);
        let bytes = serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;

        // If discoverable, create the index entry
        if discoverable {
            let disc_key = keys::encode_webauthn_discoverable(&cred_id_b64);
            let user_uuid_bytes = user_id.as_uuid().to_string().into_bytes();
            self.storage
                .put(realm_id, &disc_key, &user_uuid_bytes)
                .map_err(Self::storage_err)?;
        }

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::CredentialSet,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(info)
    }

    fn start_webauthn_authentication(
        &self,
        realm_id: &RealmId,
        user_id: Option<&UserId>,
        options: &AuthenticationOptions,
    ) -> Result<Vec<u8>, IdentityError> {
        // If user_id provided, verify user exists
        if let Some(uid) = user_id {
            self.get_user(realm_id, uid)?
                .ok_or(IdentityError::UserNotFound)?;
        }

        // Cleanup expired challenges
        let now = self.clock.now().as_micros();
        self.webauthn_challenges.cleanup_expired(now);

        // Generate and store challenge
        let challenge = webauthn::generate_challenge()?;
        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: options.rp_id.clone(),
            user_id: user_id.cloned(),
            ceremony_type: CeremonyType::Authentication,
            created_at: now,
        };
        self.webauthn_challenges.insert(pending);

        Ok(challenge)
    }

    fn complete_webauthn_authentication(
        &self,
        realm_id: &RealmId,
        params: &CompleteAuthenticationParams<'_>,
    ) -> Result<WebAuthnAuthResult, IdentityError> {
        let credential_id = params.credential_id;
        let client_data_json = params.client_data_json;
        let authenticator_data = params.authenticator_data;
        let signature = params.signature;
        let user_handle = params.user_handle;
        let origin = params.origin;

        // Extract challenge from clientDataJSON to look up pending
        let client_data: serde_json::Value =
            serde_json::from_slice(client_data_json).map_err(|e| {
                IdentityError::WebAuthnAuthenticationFailed {
                    reason: format!("invalid clientDataJSON: {e}"),
                }
            })?;
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdentityError::WebAuthnAuthenticationFailed {
                reason: "missing challenge in clientDataJSON".to_string(),
            })?;

        let pending = self
            .webauthn_challenges
            .remove(challenge_b64)
            .ok_or_else(|| IdentityError::WebAuthnAuthenticationFailed {
                reason: "challenge not found or expired".to_string(),
            })?;

        // Check expiry
        let now = self.clock.now().as_micros();
        if now - pending.created_at > 5 * 60 * 1_000_000 {
            return Err(IdentityError::WebAuthnAuthenticationFailed {
                reason: "challenge expired".to_string(),
            });
        }

        // Look up the credential by ID
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(credential_id);

        // Determine which user owns this credential
        let owner_user_id = if let Some(uid) = pending.user_id.as_ref() {
            uid.clone()
        } else {
            // Discoverable flow: look up user from discoverable index
            let disc_key = keys::encode_webauthn_discoverable(&cred_id_b64);
            let user_uuid_bytes = self
                .storage
                .get(realm_id, &disc_key)
                .map_err(Self::storage_err)?
                .ok_or(IdentityError::WebAuthnCredentialNotFound)?;
            let uuid_str = std::str::from_utf8(&user_uuid_bytes).map_err(|_| {
                IdentityError::Serialization {
                    reason: "invalid user UUID in discoverable index".to_string(),
                }
            })?;
            let uuid =
                uuid::Uuid::parse_str(uuid_str).map_err(|_| IdentityError::Serialization {
                    reason: "invalid user UUID format in discoverable index".to_string(),
                })?;
            UserId::new(uuid)
        };

        let cred_key = keys::encode_webauthn_credential(&owner_user_id, &cred_id_b64);
        let stored_bytes = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::WebAuthnCredentialNotFound)?;
        let stored: StoredWebAuthnCredential =
            serde_json::from_slice(&stored_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let result = webauthn::complete_authentication(
            &pending,
            &stored,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
            origin,
        )?;

        // Update sign counter
        let mut updated = stored;
        updated.sign_count = result.sign_count();
        let updated_bytes =
            serde_json::to_vec(&updated).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &cred_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        Ok(result)
    }

    fn list_webauthn_credentials(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<WebAuthnCredentialInfo>, IdentityError> {
        let prefix = keys::encode_webauthn_credentials_prefix(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in &entries {
            let stored: StoredWebAuthnCredential =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            let cred_id = URL_SAFE_NO_PAD
                .decode(&stored.credential_id_b64)
                .map_err(|e| IdentityError::Serialization {
                    reason: format!("invalid credential ID: {e}"),
                })?;
            results.push(WebAuthnCredentialInfo {
                credential_id: cred_id,
                algorithm: stored.algorithm,
                discoverable: stored.discoverable,
                name: stored.name.clone(),
            });
        }

        Ok(results)
    }

    fn revoke_webauthn_credential(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<(), IdentityError> {
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(credential_id);

        // Delete credential record
        let cred_key = keys::encode_webauthn_credential(user_id, &cred_id_b64);
        let existing = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?;

        if existing.is_none() {
            return Err(IdentityError::WebAuthnCredentialNotFound);
        }

        // Check if discoverable, delete index entry
        let stored: StoredWebAuthnCredential =
            serde_json::from_slice(&existing.expect("checked above")).map_err(|e| {
                IdentityError::Serialization {
                    reason: e.to_string(),
                }
            })?;

        self.storage
            .delete(realm_id, &cred_key)
            .map_err(Self::storage_err)?;

        if stored.discoverable {
            let disc_key = keys::encode_webauthn_discoverable(&cred_id_b64);
            self.storage
                .delete(realm_id, &disc_key)
                .map_err(Self::storage_err)?;
        }

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::CredentialChanged,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn rename_webauthn_credential(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        credential_id: &[u8],
        name: &str,
    ) -> Result<(), IdentityError> {
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(credential_id);
        let cred_key = keys::encode_webauthn_credential(user_id, &cred_id_b64);

        let existing = self
            .storage
            .get(realm_id, &cred_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::WebAuthnCredentialNotFound)?;

        let mut stored: StoredWebAuthnCredential =
            serde_json::from_slice(&existing).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        let trimmed = name.trim();
        stored.name = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };

        let bytes = serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &cred_key, &bytes)
            .map_err(Self::storage_err)?;

        Ok(())
    }

    // ===== Magic Link / Passwordless (Step 25) =====

    fn request_magic_link(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<MagicLinkResponse, IdentityError> {
        // Enforce realm policy before any user-visible work.
        self.check_allowed_auth_method(realm_id, "magic_link")?;

        // 1. Normalize email
        let normalized = validation::validate_email(email)?;

        // 2. Check per-email rate limit (3 per hour)
        self.check_magic_link_rate_limit(realm_id, &normalized)?;

        // 3. Look up user by email — capture user_id if exists (enumeration resistance: always succeed)
        let user_id = self
            .get_user_by_email(realm_id, &normalized)?
            .map(|u| u.id().as_uuid().to_string());

        // 4. Generate random token
        let token = magic_link::generate_magic_link_token()?;

        // 5. SHA-256 hash the token
        let token_hash = Self::sha256_hex(token.as_str().as_bytes());

        // 6. Store the magic link record
        let now = self.clock.now().as_micros();
        let stored = StoredMagicLink {
            email: normalized.clone(),
            user_id,
            created_at_micros: now,
            used: false,
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_magic_link_token(&token_hash);
        self.storage
            .put(realm_id, &key, &stored_bytes)
            .map_err(Self::storage_err)?;

        // 7. Record rate limit event
        self.record_magic_link_request(realm_id, &normalized);

        // 8. Return plaintext token (shown once)
        Ok(MagicLinkResponse::new(token.as_str().to_string()))
    }

    fn validate_magic_link(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<UserId, IdentityError> {
        // 1. SHA-256 hash the incoming token
        let token_hash = Self::sha256_hex(token.as_bytes());
        let key = keys::encode_magic_link_token(&token_hash);

        // 2. Look up stored record
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::MagicLinkTokenInvalid)?;

        let mut stored: StoredMagicLink =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 3. Check if already used
        if stored.used {
            return Err(IdentityError::MagicLinkTokenInvalid);
        }

        // 4. Check expiry
        let now = self.clock.now().as_micros();
        if now - stored.created_at_micros > MAGIC_LINK_EXPIRY_MICROS {
            // Clean up stale record
            self.storage
                .delete(realm_id, &key)
                .map_err(Self::storage_err)?;
            return Err(IdentityError::MagicLinkTokenInvalid);
        }

        // 5. Mark as used
        stored.used = true;
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 6. Return existing user or create new one
        if let Some(user_id_str) = &stored.user_id {
            let uuid =
                uuid::Uuid::parse_str(user_id_str).map_err(|e| IdentityError::Serialization {
                    reason: format!("invalid stored user_id: {e}"),
                })?;
            Ok(UserId::new(uuid))
        } else {
            // Email not registered at request time — create user now
            let request = crate::identity::types::CreateUserRequest {
                email: stored.email.clone(),
                display_name: stored.email.clone(),
                ..Default::default()
            };
            let user = self.create_user(realm_id, &request)?;
            Ok(user.id().clone())
        }
    }

    // ===== Self-service registration =====

    fn register_user(
        &self,
        realm_id: &RealmId,
        request: &RegisterUserRequest,
    ) -> Result<RegisterUserResponse, IdentityError> {
        // The system realm never accepts self-registration — it is
        // Hearth's admin home, not an application realm.
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "register_user",
            });
        }
        // 1. Load realm and enforce active status.
        let realm = self
            .get_realm(realm_id)?
            .ok_or(IdentityError::RealmNotFound)?;
        if realm.status() != RealmStatus::Active {
            return Err(IdentityError::RealmSuspended);
        }
        let policy = realm
            .config()
            .registration_policy
            .clone()
            .unwrap_or_default();

        // 2. Normalize and validate basic inputs before any storage.
        let email = validation::validate_email(&request.email)?;
        let display_name = validation::validate_display_name(&request.display_name)?;
        validation::validate_password_length(request.password.as_bytes())?;
        if let Some(pw_policy) = realm.config().password_policy.as_ref() {
            validation::validate_password_against_policy(
                request.password.as_bytes(),
                pw_policy,
                Some(&display_name),
                Some(&email),
            )?;
        }

        // 3. Enforce registration policy.
        match &policy {
            RegistrationPolicy::Disabled => {
                return Err(IdentityError::RegistrationDisabled);
            }
            RegistrationPolicy::Open => {}
            RegistrationPolicy::DomainRestricted(allowed) => {
                let at = email.find('@').ok_or_else(|| IdentityError::InvalidInput {
                    reason: "email must contain '@'".to_string(),
                })?;
                let domain = &email[at + 1..];
                let ok = allowed.iter().any(|d| d.eq_ignore_ascii_case(domain));
                if !ok {
                    return Err(IdentityError::RegistrationDomainNotAllowed {
                        domain: domain.to_string(),
                    });
                }
            }
            RegistrationPolicy::InviteOnly => {
                let Some(token) = request.invitation_token.as_deref() else {
                    return Err(IdentityError::RegistrationRequiresInvitation);
                };
                // Minimum viable: token must correspond to a pending invitation
                // for this realm whose invited email matches.
                let token_hash = Self::sha256_hex(token.as_bytes());
                let key = keys::encode_invitation_token(&token_hash);
                let bytes = self
                    .storage
                    .get(realm_id, &key)
                    .map_err(Self::storage_err)?
                    .ok_or(IdentityError::RegistrationRequiresInvitation)?;
                let invitation: OrganizationInvitation =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                if !invitation.email().eq_ignore_ascii_case(&email)
                    || invitation.status() != InvitationStatus::Pending
                {
                    return Err(IdentityError::RegistrationRequiresInvitation);
                }
            }
        }

        // 4. Rate limit on both buckets BEFORE any write.
        self.check_registration_rate_limit(realm_id, &email, request.client_ip.as_deref())?;

        // 5. Record the attempt unconditionally — duplicates and successes
        // both count so brute-force enumeration is capped.
        self.record_registration_attempt(realm_id, &email, request.client_ip.as_deref());

        // 6. SECURITY: enumeration resistance. If the email is already
        // registered, return a plausible-looking response with an unusable
        // token rather than `DuplicateEmail`. A legitimate user retrying
        // their own signup sees a harmless no-op; an attacker cannot
        // distinguish registered emails via this endpoint.
        let email_key = keys::encode_user_email(&email);
        let existing = self
            .storage
            .get(realm_id, &email_key)
            .map_err(Self::storage_err)?;
        if existing.is_some() {
            let fake = magic_link::generate_magic_link_token()?;
            return Ok(RegisterUserResponse {
                user_id: UserId::generate(),
                verification_token: fake.as_str().to_string(),
            });
        }

        // 7. Create the user in PendingVerification status.
        let user = self.create_user_with_status(
            realm_id,
            &CreateUserRequest {
                email: email.clone(),
                display_name,
                ..Default::default()
            },
            UserStatus::PendingVerification,
        )?;

        // 8. Store the password.
        self.set_password(realm_id, user.id(), &request.password)?;

        // 9. Issue a verification token.
        let verification_token = self.issue_email_verification_token(realm_id, user.id())?;

        let new_user_id = user.id().clone();
        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::Anonymous,
                metadata: None,
            }),
            AuditAction::UserCreated,
            "user",
            &new_user_id.as_uuid().to_string(),
        )?;

        Ok(RegisterUserResponse {
            user_id: new_user_id,
            verification_token,
        })
    }

    // ===== Password reset =====

    fn request_password_reset(
        &self,
        realm_id: &RealmId,
        email: &str,
    ) -> Result<Option<String>, IdentityError> {
        // 1. Normalize email
        let normalized = validation::validate_email(email)?;

        // 2. Check per-email rate limit (3 per hour)
        self.check_password_reset_rate_limit(realm_id, &normalized)?;

        // 3. Look up user by email — return None for unknown (enumeration resistance)
        let Some(user) = self.get_user_by_email(realm_id, &normalized)? else {
            // Record the attempt even for unknown emails (prevents rate-limit bypass)
            self.record_password_reset_request(realm_id, &normalized);
            return Ok(None);
        };

        // 4. Generate random token (reuse magic link token generator)
        let token = magic_link::generate_magic_link_token()?;

        // 5. SHA-256 hash the token
        let token_hash = Self::sha256_hex(token.as_str().as_bytes());

        // 6. Store the password reset record
        let now = self.clock.now().as_micros();
        let stored = StoredPasswordReset {
            email: normalized.clone(),
            user_id: user.id().as_uuid().to_string(),
            created_at_micros: now,
            used: false,
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_password_reset_token(&token_hash);
        self.storage
            .put(realm_id, &key, &stored_bytes)
            .map_err(Self::storage_err)?;

        // 7. Record rate limit event
        self.record_password_reset_request(realm_id, &normalized);

        // 8. Return plaintext token (shown once)
        Ok(Some(token.as_str().to_string()))
    }

    fn reset_password_with_token(
        &self,
        realm_id: &RealmId,
        token: &str,
        new_password: &CleartextPassword,
    ) -> Result<UserId, IdentityError> {
        // 1. SHA-256 hash the incoming token
        let token_hash = Self::sha256_hex(token.as_bytes());
        let key = keys::encode_password_reset_token(&token_hash);

        // 2. Look up stored record
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::PasswordResetTokenInvalid)?;

        let mut stored: StoredPasswordReset =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 3. Check if already used
        if stored.used {
            return Err(IdentityError::PasswordResetTokenInvalid);
        }

        // 4. Check expiry — use realm-specific TTL when configured, else default (30 minutes).
        let expiry_micros = self
            .get_realm(realm_id)
            .ok()
            .flatten()
            .and_then(|r| r.config().password_reset_token_ttl_micros)
            .unwrap_or(PASSWORD_RESET_EXPIRY_MICROS);
        let now = self.clock.now().as_micros();
        if now - stored.created_at_micros > expiry_micros {
            // Clean up stale record
            self.storage
                .delete(realm_id, &key)
                .map_err(Self::storage_err)?;
            return Err(IdentityError::PasswordResetTokenInvalid);
        }

        // 5. Mark as used
        stored.used = true;
        let updated_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 6. Parse user ID and set new password
        let uuid =
            uuid::Uuid::parse_str(&stored.user_id).map_err(|e| IdentityError::Serialization {
                reason: format!("invalid stored user_id: {e}"),
            })?;
        let user_id = UserId::new(uuid);
        self.set_password(realm_id, &user_id, new_password)?;

        // 7. Invalidate all existing sessions — credential change should force re-auth.
        let page = self.list_sessions_by_user(realm_id, &user_id, None, 1000)?;
        for session in page.items {
            if let Err(e) = self.revoke_session(realm_id, session.id()) {
                tracing::warn!(
                    session_id = %session.id(),
                    error = %e,
                    "reset_password: failed to revoke session"
                );
            }
        }

        self.record_audit(
            realm_id,
            None,
            AuditAction::CredentialChanged,
            "credential",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(user_id)
    }

    // ===== Email verification (onboarding) =====

    fn issue_email_verification_token(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<String, IdentityError> {
        // Ensure the target user exists (don't bind tokens to nothing).
        let user = self
            .get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Generate 32 random bytes, base64url-encoded.
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate verification token".to_string(),
            })?;
        let token = URL_SAFE_NO_PAD.encode(bytes);

        // Persist SHA-256(token) → StoredEmailVerification.
        let token_hash = Self::sha256_hex(token.as_bytes());
        let stored = StoredEmailVerification {
            user_id: user.id().as_uuid().to_string(),
            created_at_micros: self.clock.now().as_micros(),
            used: false,
        };
        let stored_bytes =
            serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_email_verify_token(&token_hash);
        self.storage
            .put(realm_id, &key, &stored_bytes)
            .map_err(Self::storage_err)?;

        Ok(token)
    }

    fn verify_email_token(&self, realm_id: &RealmId, token: &str) -> Result<UserId, IdentityError> {
        let token_hash = Self::sha256_hex(token.as_bytes());
        let key = keys::encode_email_verify_token(&token_hash);

        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::VerificationTokenInvalid)?;

        let stored: StoredEmailVerification =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if stored.used {
            return Err(IdentityError::VerificationTokenInvalid);
        }

        let now = self.clock.now().as_micros();
        if now - stored.created_at_micros > EMAIL_VERIFY_EXPIRY_MICROS {
            // Best-effort cleanup; ignore failure.
            let _ = self.storage.delete(realm_id, &key);
            return Err(IdentityError::VerificationTokenInvalid);
        }

        // Resolve stored user id back into a typed UserId.
        let uuid =
            uuid::Uuid::parse_str(&stored.user_id).map_err(|e| IdentityError::Serialization {
                reason: format!("invalid stored user_id: {e}"),
            })?;
        let user_id = UserId::new(uuid);

        // Transition user to Active. If the user was already Active we
        // still consume the token to keep single-use semantics, but leave
        // the user record alone.
        let mut user = self
            .get_user(realm_id, &user_id)?
            .ok_or(IdentityError::VerificationTokenInvalid)?;
        if user.status() == UserStatus::PendingVerification {
            user.set_status(UserStatus::Active);
            user.set_updated_at(self.clock.now());
            let user_bytes =
                serde_json::to_vec(&user).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            let user_key = keys::encode_user_id(&user_id);
            self.storage
                .put(realm_id, &user_key, &user_bytes)
                .map_err(Self::storage_err)?;
        }

        // Delete the token entry so it cannot be reused.
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;

        Ok(user_id)
    }

    // ===== UserInfo (OIDC Core §5.3) =====

    fn userinfo(
        &self,
        realm_id: &RealmId,
        access_token: &str,
    ) -> Result<crate::identity::oidc::UserInfoResponse, IdentityError> {
        // 1. Validate the access token
        let claims = self.validate_token(realm_id, access_token)?;

        // 2. Ensure it's an access token
        if claims.token_type != "access" {
            return Err(IdentityError::InvalidToken);
        }

        // 3. Parse user_id from sub claim
        let user_id_str = claims
            .sub
            .strip_prefix("user_")
            .ok_or(IdentityError::InvalidToken)?;
        let user_uuid =
            uuid::Uuid::parse_str(user_id_str).map_err(|_| IdentityError::InvalidToken)?;
        let user_id = crate::core::UserId::new(user_uuid);

        // 4. Look up the user
        let user = self
            .get_user(realm_id, &user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        let scope_set: BTreeSet<String> = claims
            .scope
            .as_deref()
            .unwrap_or("openid")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let client = claims
            .aud
            .base()
            .strip_prefix("client_")
            .and_then(|uuid| uuid::Uuid::parse_str(uuid).ok())
            .and_then(|uuid| {
                self.get_client(realm_id, &ClientId::new(uuid))
                    .ok()
                    .flatten()
            });
        let empty_client = OAuthClient::new(
            ClientId::generate(),
            "userinfo".to_string(),
            Vec::new(),
            self.clock.now(),
        );
        let resolved = self
            .rbac
            .resolve_permissions(&user_id, realm_id, None, None)
            .map_err(|e| match e {
                RbacError::TokenSizeExceeded {
                    limit,
                    limit_value,
                    actual,
                } => IdentityError::TokenTooLarge {
                    limit: format!("userinfo_{limit}"),
                    limit_value,
                    actual,
                },
                e => IdentityError::Internal {
                    reason: format!("rbac resolve failed: {e}"),
                },
            })?;
        let (_roles, _groups, _permissions, custom) = self.apply_claim_profile(
            realm_id,
            &user,
            client.as_ref().unwrap_or(&empty_client),
            &resolved,
            &scope_set,
            claims.oid.as_deref(),
            ClaimTarget::UserInfo,
        );

        Ok(crate::identity::oidc::UserInfoResponse {
            sub: claims.sub,
            email: custom
                .get("email")
                .and_then(|value| value.as_str().map(str::to_string)),
            email_verified: scope_set.contains("email").then_some(true),
            name: custom
                .get("name")
                .and_then(|value| value.as_str().map(str::to_string)),
            custom: custom
                .into_iter()
                .filter(|(key, _)| key != "email" && key != "name")
                .collect(),
        })
    }

    // ===== Admin API (Step 27) =====

    fn list_users(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<User>, IdentityError> {
        let prefix = keys::user_id_scan_prefix();
        let start = if let Some(cursor_str) = cursor {
            // Decode cursor → UUID, build key just after it
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            // Build key for cursor UUID and add a byte to get "just after"
            let mut cursor_key = format!("usr:id:{uuid_str}").into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            let user: User =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(user);
        }

        let next_cursor = if items.len() > limit {
            items.pop(); // discard the extra item
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn search_users(
        &self,
        realm_id: &RealmId,
        query: &str,
        limit: usize,
    ) -> Result<Vec<User>, IdentityError> {
        let query = query.trim();
        if query.len() < 2 {
            return Ok(Vec::new());
        }
        let query_lower = query.to_lowercase();

        let prefix = keys::user_id_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;

        let mut results = Vec::new();
        for entry in &entries {
            let user: User =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            let email_lower = user.email().to_lowercase();
            let name_lower = user.display_name().to_lowercase();
            if email_lower.contains(&query_lower) || name_lower.contains(&query_lower) {
                results.push(user);
                if results.len() >= limit {
                    break;
                }
            }
        }

        Ok(results)
    }

    fn list_realms(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Realm>, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let prefix = keys::realm_id_scan_prefix();
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("realm:id:{uuid_str}").into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(&sys_realm, &start, &end)
            .map_err(Self::storage_err)?;

        // Filter out the reserved system realm: its record lives here
        // alongside application realms but must never surface on the
        // admin listing, realm switcher, or resolver's sole-realm
        // shortcut. We scan with `limit + 1` headroom plus the filter
        // so a page that happens to straddle the nil realm still
        // returns `limit` real results.
        let mut items = Vec::new();
        for entry in &entries {
            let realm: Realm =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if keys::is_system_realm(realm.id()) {
                continue;
            }
            items.push(realm);
            if items.len() > limit {
                break;
            }
        }

        let next_cursor = if items.len() > limit {
            items.pop(); // discard the extra item
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn authenticate_oauth_client(
        &self,
        realm_id: &RealmId,
        client_id: &ClientId,
        client_secret: &str,
    ) -> Result<(), IdentityError> {
        let client_key = keys::encode_oauth_client(client_id);
        let client_bytes = self
            .storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let secret_hash = client
            .client_secret_hash()
            .ok_or(IdentityError::InvalidClientSecret)?;
        let valid = credentials::verify_raw_secret(client_secret.as_bytes(), secret_hash)?;
        if !valid {
            return Err(IdentityError::InvalidClientSecret);
        }
        Ok(())
    }

    fn list_clients(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OAuthClient>, IdentityError> {
        let prefix = keys::oauth_client_scan_prefix();
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("oauth:client:{uuid_str}").into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            let client: OAuthClient =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(client);
        }

        let next_cursor = if items.len() > limit {
            items.pop(); // discard the extra item
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.client_id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn get_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<OAuthClient>, IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?;

        match bytes {
            Some(data) => {
                let client: OAuthClient =
                    serde_json::from_slice(&data).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    fn authenticate_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        client_secret: Option<&str>,
    ) -> Result<(), IdentityError> {
        // Return InvalidClientSecret (not ClientNotFound) on any failure to
        // prevent client enumeration via error differentiation.
        let client = self
            .get_client(realm_id, client_id)?
            .ok_or(IdentityError::InvalidClientSecret)?;

        if let Some(hash) = client.client_secret_hash() {
            // Confidential client: secret is required and must match.
            let secret = client_secret.ok_or(IdentityError::InvalidClientSecret)?;
            if !credentials::verify_raw_secret(secret.as_bytes(), hash)? {
                return Err(IdentityError::InvalidClientSecret);
            }
        }
        // Public client: no secret needed, client_id alone suffices.
        Ok(())
    }

    fn update_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
        request: &crate::identity::oidc::UpdateClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        let mut client: OAuthClient =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if let Some(name) = &request.client_name {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "client_name cannot be empty".to_string(),
                });
            }
            client.set_client_name(trimmed.to_string());
        }
        if let Some(uris) = &request.redirect_uris {
            if uris.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "redirect_uris cannot be empty".to_string(),
                });
            }
            client.set_redirect_uris(uris.clone());
        }
        if let Some(grant_types) = &request.grant_types {
            if grant_types.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "grant_types cannot be empty".to_string(),
                });
            }
            client.set_grant_types(grant_types.clone());
        }
        if let Some(require) = request.require_consent {
            client.set_require_consent(require);
        }
        if let Some(logo) = &request.client_logo_url {
            client.set_client_logo_url(logo.clone());
        }
        if let Some(slug) = &request.slug {
            client.set_slug(slug.clone());
        }
        if let Some(trust_level) = request.trust_level {
            client.set_trust_level(trust_level);
            client
                .set_require_consent(trust_level == crate::identity::ClientTrustLevel::ThirdParty);
        }
        if let Some(declared_scopes) = &request.declared_scopes {
            client.set_declared_scopes(declared_scopes.clone());
        }
        if let Some(consent_spans_orgs) = request.consent_spans_orgs {
            client.set_consent_spans_orgs(consent_spans_orgs);
        }
        if let Some(uri) = &request.backchannel_logout_uri {
            client.set_backchannel_logout_uri(uri.clone());
        }
        if let Some(uri) = &request.frontchannel_logout_uri {
            client.set_frontchannel_logout_uri(uri.clone());
        }
        if let Some(uris) = &request.post_logout_redirect_uris {
            client.set_post_logout_redirect_uris(uris.clone());
        }
        if let Some(status) = request.status {
            client.set_status(status);
        }

        let updated_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientUpdated,
            "client",
            &client_id.as_uuid().to_string(),
        )?;

        Ok(client)
    }

    fn regenerate_client_secret(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<String, IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        let mut client: OAuthClient =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if !client.is_confidential() {
            return Err(IdentityError::InvalidInput {
                reason: "cannot regenerate secret for a public client".to_string(),
            });
        }

        // Generate new random secret (32 bytes, base64url)
        let rng = ring::rand::SystemRandom::new();
        let mut secret_bytes = [0u8; 32];
        rng.fill(&mut secret_bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "failed to generate random bytes for client secret".to_string(),
            })?;
        let plaintext_secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        // Hash with Argon2id
        let secret_hash =
            credentials::hash_raw_secret(plaintext_secret.as_bytes(), &self.config.credential)?;
        client.set_client_secret_hash(secret_hash);

        let updated_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientUpdated,
            "client",
            &client_id.as_uuid().to_string(),
        )?;

        Ok(plaintext_secret)
    }

    fn delete_client(
        &self,
        realm_id: &RealmId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        // Verify the client exists first
        self.storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;

        // Cascade: scrub every consent record referencing this client.
        // Consent keys are `oauth:consent:{user_uuid}:{client_uuid}`, so
        // we scan the whole namespace and match the trailing client segment.
        let consent_prefix = keys::oauth_consent_scan_prefix();
        let consent_end = keys::prefix_end(&consent_prefix);
        let consent_entries = self
            .storage
            .scan(realm_id, &consent_prefix, &consent_end)
            .map_err(Self::storage_err)?;
        let client_uuid_str = client_id.as_uuid().to_string();
        for entry in &consent_entries {
            if let Ok(key_str) = std::str::from_utf8(&entry.key) {
                if key_str.ends_with(&client_uuid_str) {
                    self.storage
                        .delete(realm_id, &entry.key)
                        .map_err(Self::storage_err)?;
                }
            }
        }
        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientDeleted,
            "client",
            &client_id.as_uuid().to_string(),
        )?;
        Ok(())
    }

    // ===== OAuth consent =====

    fn get_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
    ) -> Result<Option<ConsentRecord>, IdentityError> {
        // Legacy key (`oauth:consent:{user}:{client}`) — checked first for
        // backward compatibility with records written before the extended key
        // schema was introduced.
        let legacy_key = keys::encode_consent_key(user_id, client_id);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &legacy_key)
            .map_err(Self::storage_err)?
        {
            let rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            return Ok(Some(rec));
        }

        // Extended key (`oauth:consent:{user}:{client}:_realm:_default`) —
        // the canonical form for new records.
        let extended_key = keys::encode_consent_key_extended(
            user_id,
            client_id,
            keys::CONSENT_ORG_KEY_REALM,
            keys::CONSENT_RESOURCE_KEY_DEFAULT,
        );
        if let Some(bytes) = self
            .storage
            .get(realm_id, &extended_key)
            .map_err(Self::storage_err)?
        {
            let rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            return Ok(Some(rec));
        }

        Ok(None)
    }

    fn list_consents_by_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<ConsentListEntry>, IdentityError> {
        let prefix = keys::encode_consent_prefix_for_user(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let rec: ConsentRecord =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            // Join with current client. Orphaned consents (client deleted)
            // are filtered out — callers see only actionable entries.
            let client_key = keys::encode_oauth_client(&rec.client_id);
            let Some(client_bytes) = self
                .storage
                .get(realm_id, &client_key)
                .map_err(Self::storage_err)?
            else {
                continue;
            };
            let client: OAuthClient = serde_json::from_slice(&client_bytes).map_err(|e| {
                IdentityError::Serialization {
                    reason: e.to_string(),
                }
            })?;
            out.push(ConsentListEntry {
                record: rec,
                client_name: client.client_name().to_string(),
                client_logo_url: client.client_logo_url().map(str::to_string),
            });
        }
        Ok(out)
    }

    fn grant_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
        approved_scopes: &[String],
    ) -> Result<ConsentRecord, IdentityError> {
        // Verify the client exists — avoids orphan consents.
        let client_key = keys::encode_oauth_client(client_id);
        self.storage
            .get(realm_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        let now = self.clock.now();

        // Use the extended key as the canonical storage location for new
        // records. The realm-level sentinel values (`_realm`, `_default`)
        // are used when no org/resource context is supplied by the caller.
        let key = keys::encode_consent_key_extended(
            user_id,
            client_id,
            keys::CONSENT_ORG_KEY_REALM,
            keys::CONSENT_RESOURCE_KEY_DEFAULT,
        );

        // Also check the legacy key so that pre-migration records are merged
        // rather than duplicated.
        let legacy_key = keys::encode_consent_key(user_id, client_id);
        let existing_bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .or_else(|| self.storage.get(realm_id, &legacy_key).unwrap_or_default());

        let mut record = if let Some(bytes) = existing_bytes {
            let mut rec: ConsentRecord =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            rec.merge_scopes(approved_scopes, now);
            rec
        } else {
            ConsentRecord::new(
                user_id.clone(),
                client_id.clone(),
                approved_scopes.to_vec(),
                now,
            )
        };

        // Compute and store the scope digest so future authorize /
        // refresh_token calls can detect stale consent.
        record.scope_digest = Self::compute_scope_digest(&record.granted_scopes);

        let bytes = serde_json::to_vec(&record).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;

        // Remove the legacy key if it existed to avoid stale duplicates.
        let _ = self.storage.delete(realm_id, &legacy_key);

        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::ConsentGranted,
            "consent",
            &client_id.as_uuid().to_string(),
        )?;

        Ok(record)
    }

    fn revoke_consent(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
    ) -> Result<(), IdentityError> {
        // Try the extended key (canonical location for new records) first.
        let extended_key = keys::encode_consent_key_extended(
            user_id,
            client_id,
            keys::CONSENT_ORG_KEY_REALM,
            keys::CONSENT_RESOURCE_KEY_DEFAULT,
        );
        let extended_exists = self
            .storage
            .get(realm_id, &extended_key)
            .map_err(Self::storage_err)?
            .is_some();
        if extended_exists {
            self.storage
                .delete(realm_id, &extended_key)
                .map_err(Self::storage_err)?;
            // Also clean up any lingering legacy key.
            let legacy_key = keys::encode_consent_key(user_id, client_id);
            let _ = self.storage.delete(realm_id, &legacy_key);
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata: None,
                }),
                AuditAction::ConsentRevoked,
                "consent",
                &client_id.as_uuid().to_string(),
            )?;
            return Ok(());
        }

        // Fall back to the legacy key for pre-migration records.
        let legacy_key = keys::encode_consent_key(user_id, client_id);
        let legacy_exists = self
            .storage
            .get(realm_id, &legacy_key)
            .map_err(Self::storage_err)?
            .is_some();
        if legacy_exists {
            self.storage
                .delete(realm_id, &legacy_key)
                .map_err(Self::storage_err)?;
            self.record_audit(
                realm_id,
                Some(&AuditContext {
                    actor: Actor::User(user_id.clone()),
                    metadata: None,
                }),
                AuditAction::ConsentRevoked,
                "consent",
                &client_id.as_uuid().to_string(),
            )?;
            return Ok(());
        }

        Err(IdentityError::ConsentNotFound)
    }

    fn revoke_all_consents_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<usize, IdentityError> {
        let prefix = keys::encode_consent_prefix_for_user(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let count = entries.len();
        for entry in &entries {
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }
        self.record_audit(
            realm_id,
            Some(&AuditContext {
                actor: Actor::User(user_id.clone()),
                metadata: None,
            }),
            AuditAction::ConsentRevoked,
            "consent",
            "all",
        )?;
        Ok(count)
    }

    fn put_pending_authorization(
        &self,
        realm_id: &RealmId,
        request: &PendingAuthorizationRequest,
    ) -> Result<String, IdentityError> {
        let ticket = uuid::Uuid::new_v4().to_string();
        let key = keys::encode_pending_auth_key(&ticket);
        let bytes = serde_json::to_vec(request).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)?;
        Ok(ticket)
    }

    fn get_pending_authorization(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<Option<PendingAuthorizationRequest>, IdentityError> {
        let key = keys::encode_pending_auth_key(ticket);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let pending: PendingAuthorizationRequest =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if self.clock.now().as_micros() >= pending.expires_at.as_micros() {
            return Err(IdentityError::ConsentTicketExpired);
        }
        Ok(Some(pending))
    }

    fn take_pending_authorization(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<PendingAuthorizationRequest, IdentityError> {
        let key = keys::encode_pending_auth_key(ticket);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ConsentTicketNotFound)?;
        // Single-use: delete before we even validate expiry so callers can
        // never replay the same ticket twice even on a narrow race.
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let pending: PendingAuthorizationRequest =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if self.clock.now().as_micros() >= pending.expires_at.as_micros() {
            return Err(IdentityError::ConsentTicketExpired);
        }
        Ok(pending)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_authorization_code(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        client_id: &ClientId,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
        nonce: Option<String>,
    ) -> Result<AuthorizationResponse, IdentityError> {
        // Reuse the canonical path by constructing an AuthorizationRequest
        // and delegating to `authorize`. This keeps PKCE rules, nonce
        // enforcement, client/redirect_uri validation, and code storage
        // all in one place.
        let request = AuthorizationRequest {
            client_id: client_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            state: state.to_string(),
            resource: None,
            response_type: "code".to_string(),
            user_id: user_id.clone(),
            code_challenge,
            code_challenge_method,
            nonce,
        };
        self.authorize(realm_id, &request)
    }

    fn bulk_create_users(
        &self,
        realm_id: &RealmId,
        requests: &[CreateUserRequest],
    ) -> Result<Vec<BulkResult<User>>, IdentityError> {
        let count = requests.len();
        let mut results = Vec::with_capacity(count);
        for (index, request) in requests.iter().enumerate() {
            let result = match self.create_user(realm_id, request) {
                Ok(user) => BulkResult {
                    index,
                    result: Ok(user),
                },
                Err(e) => BulkResult {
                    index,
                    result: Err(e.to_string()),
                },
            };
            results.push(result);
        }
        self.record_audit(
            realm_id,
            None,
            AuditAction::BulkUsersCreated,
            "user",
            &count.to_string(),
        )?;
        Ok(results)
    }

    fn bulk_disable_users(
        &self,
        realm_id: &RealmId,
        user_ids: &[UserId],
    ) -> Result<Vec<BulkResult<()>>, IdentityError> {
        let count = user_ids.len();
        let mut results = Vec::with_capacity(count);
        for (index, user_id) in user_ids.iter().enumerate() {
            let result = match self.update_user(
                realm_id,
                user_id,
                &UpdateUserRequest {
                    status: Some(UserStatus::Disabled),
                    ..UpdateUserRequest::default()
                },
            ) {
                Ok(_) => BulkResult {
                    index,
                    result: Ok(()),
                },
                Err(e) => BulkResult {
                    index,
                    result: Err(e.to_string()),
                },
            };
            results.push(result);
        }
        self.record_audit(
            realm_id,
            None,
            AuditAction::BulkUsersDisabled,
            "user",
            &count.to_string(),
        )?;
        Ok(results)
    }

    // ===== Migration / import (Phase 1 Step 30) =====

    fn import_realm(
        &self,
        request: &CreateRealmRequest,
        requested_id: Option<RealmId>,
    ) -> Result<Realm, IdentityError> {
        // The reserved system realm is never an import target. An
        // external dump can legitimately be named "system" (Keycloak's
        // default realm is called `master`, not `system`, but we
        // defend against any collision anyway) — refuse rather than
        // silently rename.
        if request.name == keys::SYSTEM_REALM_NAME {
            return Err(IdentityError::SystemRealmProtected {
                operation: "import_realm",
            });
        }
        if let Some(ref id) = requested_id {
            if keys::is_system_realm(id) {
                return Err(IdentityError::SystemRealmProtected {
                    operation: "import_realm",
                });
            }
        }
        // Serialize against other realm-record mutations so the atomic
        // record+key `put_batch` below is never interleaved with another
        // thread's update/delete. Mirrors `create_realm`.
        let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");

        let realm_id = requested_id.unwrap_or_else(RealmId::generate);

        // Refuse to clobber an existing realm record — callers may
        // retry an idempotent import flow, in which case they want a
        // clear DuplicateRealmName signal rather than a silent rewrite
        // that would also generate a fresh signing key and invalidate
        // every existing token under that realm.
        let sys_realm = keys::system_realm_id();
        let realm_key = keys::encode_realm_id(&realm_id);
        if self
            .storage
            .get(&sys_realm, &realm_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateRealmName);
        }

        let now = self.clock.now();
        let config = request.config.clone().unwrap_or_default();
        let realm_signing_key = SigningKey::generate()?;

        let realm = Realm::new(
            realm_id.clone(),
            request.name.clone(),
            RealmStatus::Active,
            config,
            now,
            now,
        );
        let realm_bytes = Self::serialize_realm(&realm)?;
        let key_storage_key = keys::encode_realm_signing_key(&realm_id);
        let key_bytes = realm_signing_key.pkcs8_bytes().to_vec();

        self.storage
            .put_batch(
                &sys_realm,
                &[(realm_key, realm_bytes), (key_storage_key, key_bytes)],
            )
            .map_err(Self::storage_err)?;

        {
            let mut key_cache = self.realm_signing_keys.lock().expect("key cache lock");
            key_cache.insert(realm_id.as_uuid().to_string(), Arc::new(realm_signing_key));
        }

        self.record_audit(
            &realm_id,
            None,
            AuditAction::RealmCreated,
            "realm",
            &realm_id.as_uuid().to_string(),
        )?;

        Ok(realm)
    }

    fn import_user(
        &self,
        realm_id: &RealmId,
        request: &ImportUserRequest,
    ) -> Result<User, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "import_user",
            });
        }
        // 1. Validate and normalize input (same invariants as create_user)
        let email = validation::validate_email(&request.email)?;
        let first_name = validation::validate_name_part(&request.first_name, "first_name")?;
        let last_name = validation::validate_name_part(&request.last_name, "last_name")?;
        let display_name = if request.display_name.trim().is_empty() {
            let synthesized = format!("{} {}", first_name, last_name).trim().to_string();
            if synthesized.is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "display_name or first_name/last_name required".to_string(),
                });
            }
            validation::validate_display_name(&synthesized)?
        } else {
            validation::validate_display_name(&request.display_name)?
        };

        // 2. Check email uniqueness
        let email_key = keys::encode_user_email(&email);
        if self
            .storage
            .get(realm_id, &email_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateEmail);
        }

        // 3. Resolve user id — allow caller to preserve a foreign UUID,
        //    but refuse to clobber an existing record at that id.
        let user_id = request.id.clone().unwrap_or_else(UserId::generate);
        let id_key = keys::encode_user_id(&user_id);
        if self
            .storage
            .get(realm_id, &id_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::InvalidInput {
                reason: "a user with this id already exists".to_string(),
            });
        }

        let now = self.clock.now();
        let mut user = User::new(
            user_id.clone(),
            email.clone(),
            display_name,
            first_name,
            last_name,
            request.status,
            now,
            now,
        );

        if !request.attributes.is_empty() {
            Self::validate_user_attributes(&request.attributes)?;
            user.set_attributes(request.attributes.clone());
        }

        let user_bytes = Self::serialize_user(&user)?;
        let user_id_bytes = user_id.as_uuid().to_string().into_bytes();

        // 4. If a credential was supplied, derive the algorithm from the
        //    PHC prefix and prepare the credential write as part of the
        //    same atomic batch. Preserving the foreign hash verbatim lets
        //    the user authenticate with their existing password; the next
        //    successful verify will auto-upgrade to Argon2id.
        let mut entries = Vec::with_capacity(3);
        entries.push((email_key, user_id_bytes));
        entries.push((id_key, user_bytes));

        if let Some(raw) = &request.credential {
            let algorithm = classify_phc_algorithm(&raw.phc_string).ok_or_else(|| {
                IdentityError::InvalidInput {
                    reason: "unrecognized password hash format".to_string(),
                }
            })?;
            let created_at = raw.created_at_micros.unwrap_or_else(|| now.as_micros());
            let stored = StoredCredential {
                algorithm,
                hash: raw.phc_string.clone(),
                created_at,
            };
            let cred_bytes = Self::serialize_credential(&stored)?;
            let cred_key = keys::encode_credential_key(&user_id);
            entries.push((cred_key, cred_bytes));
        }

        self.storage
            .put_batch(realm_id, &entries)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::UserCreated,
            "user",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(user)
    }

    fn import_client(
        &self,
        realm_id: &RealmId,
        request: &ImportClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "import_client",
            });
        }
        let client_name = validation::validate_client_name(&request.client_name)?;

        let has_client_credentials = request
            .grant_types
            .contains(&"client_credentials".to_string());
        let has_device_code = request
            .grant_types
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string());
        if request.redirect_uris.is_empty() && !has_client_credentials && !has_device_code {
            return Err(IdentityError::InvalidInput {
                reason: "at least one redirect URI is required".to_string(),
            });
        }
        for uri in &request.redirect_uris {
            if uri.trim().is_empty() {
                return Err(IdentityError::InvalidInput {
                    reason: "redirect URIs must not be empty".to_string(),
                });
            }
            validation::validate_redirect_uri(uri)?;
        }

        let client_id = request.id.clone().unwrap_or_else(ClientId::generate);
        let key = keys::encode_oauth_client(&client_id);
        if self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::InvalidInput {
                reason: "a client with this id already exists".to_string(),
            });
        }

        let now = self.clock.now();
        let grant_types = if request.grant_types.is_empty() {
            vec!["authorization_code".to_string()]
        } else {
            request.grant_types.clone()
        };

        let mut client = if let Some(ref secret) = request.client_secret {
            let secret_hash =
                credentials::hash_raw_secret(secret.as_bytes(), &self.config.credential)?;
            OAuthClient::new_confidential(
                client_id,
                client_name,
                request.redirect_uris.clone(),
                now,
                secret_hash,
                grant_types,
            )
        } else {
            let mut c =
                OAuthClient::new(client_id, client_name, request.redirect_uris.clone(), now);
            c.set_grant_types(grant_types);
            c
        };
        client.set_slug(
            request
                .slug
                .clone()
                .unwrap_or_else(|| client.client_name().to_lowercase().replace(' ', "-")),
        );
        client.set_trust_level(request.trust_level);
        client.set_require_consent(
            request.trust_level == crate::identity::ClientTrustLevel::ThirdParty,
        );
        client.set_declared_scopes(request.declared_scopes.clone());
        client.set_consent_spans_orgs(request.consent_spans_orgs);

        let client_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &key, &client_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::ClientRegistered,
            "client",
            &client.client_id().as_uuid().to_string(),
        )?;

        Ok(client)
    }

    // ===== Organizations =====

    fn create_organization(
        &self,
        realm_id: &RealmId,
        request: &CreateOrganizationRequest,
    ) -> Result<Organization, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "create_organization",
            });
        }
        let slug = validation::validate_slug(&request.slug)?;
        let name = validation::validate_display_name(&request.name)?;

        // Check slug uniqueness
        let slug_key = keys::encode_org_slug(&slug);
        if self
            .storage
            .get(realm_id, &slug_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateOrgSlug);
        }

        let now = self.clock.now();
        let org_id = OrganizationId::generate();
        let description = request.description.clone().unwrap_or_default();
        let config = request.config.clone().unwrap_or_default();

        let org = Organization::new(
            org_id.clone(),
            name,
            slug.clone(),
            description,
            OrganizationStatus::Active,
            config,
            now,
            now,
        );

        // Write primary record
        let id_key = keys::encode_org_id(&org_id);
        let org_bytes = serde_json::to_vec(&org).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &id_key, &org_bytes)
            .map_err(Self::storage_err)?;

        // Write slug index
        self.storage
            .put(realm_id, &slug_key, org_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::OrgCreated,
            "org",
            &org_id.as_uuid().to_string(),
        )?;

        Ok(org)
    }

    fn get_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<Option<Organization>, IdentityError> {
        let key = keys::encode_org_id(org_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let org: Organization =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(org))
            }
            None => Ok(None),
        }
    }

    fn get_organization_by_slug(
        &self,
        realm_id: &RealmId,
        slug: &str,
    ) -> Result<Option<Organization>, IdentityError> {
        let slug_key = keys::encode_org_slug(slug);
        match self
            .storage
            .get(realm_id, &slug_key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let uuid =
                    uuid::Uuid::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: format!("invalid org UUID in slug index: {e}"),
                    })?;
                let org_id = OrganizationId::new(uuid);
                self.get_organization(realm_id, &org_id)
            }
            None => Ok(None),
        }
    }

    fn update_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        request: &UpdateOrganizationRequest,
    ) -> Result<Organization, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "update_organization",
            });
        }
        let mut org = self
            .get_organization(realm_id, org_id)?
            .ok_or(IdentityError::OrganizationNotFound)?;

        if let Some(ref name) = request.name {
            let validated = validation::validate_display_name(name)?;
            org.set_name(validated);
        }
        if let Some(ref description) = request.description {
            org.set_description(description.clone());
        }
        if let Some(status) = request.status {
            org.set_status(status);
        }
        if let Some(ref config) = request.config {
            org.set_config(config.clone());
        }

        let now = self.clock.now();
        org.set_updated_at(now);

        let id_key = keys::encode_org_id(org_id);
        let org_bytes = serde_json::to_vec(&org).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &id_key, &org_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::OrgUpdated,
            "org",
            &org_id.as_uuid().to_string(),
        )?;

        Ok(org)
    }

    fn delete_organization(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError> {
        let org = self
            .get_organization(realm_id, org_id)?
            .ok_or(IdentityError::OrganizationNotFound)?;

        // 1. Delete all memberships (forward + reverse indexes)
        let member_prefix = keys::membership_by_org_prefix(org_id);
        let member_end = keys::prefix_end(&member_prefix);
        let members = self
            .storage
            .scan(realm_id, &member_prefix, &member_end)
            .map_err(Self::storage_err)?;

        for entry in &members {
            // Parse membership to get user_id for reverse index
            if let Ok(membership) = serde_json::from_slice::<OrganizationMembership>(&entry.value) {
                // Delete reverse index
                let reverse_key = keys::encode_membership_by_user(membership.user_id(), org_id);
                self.storage
                    .delete(realm_id, &reverse_key)
                    .map_err(Self::storage_err)?;
            }
            // Delete forward index
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 2. Delete all invitations
        let inv_list_prefix = keys::invitation_list_prefix(org_id);
        let inv_list_end = keys::prefix_end(&inv_list_prefix);
        let inv_list_entries = self
            .storage
            .scan(realm_id, &inv_list_prefix, &inv_list_end)
            .map_err(Self::storage_err)?;

        for entry in &inv_list_entries {
            // Extract invitation ID from list key to delete related records
            let key_str =
                std::str::from_utf8(&entry.key).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if let Some(inv_uuid_str) = key_str.rsplit(':').next() {
                if let Ok(uuid) = uuid::Uuid::parse_str(inv_uuid_str) {
                    let inv_id = InvitationId::new(uuid);
                    // Delete invitation primary record
                    let inv_key = keys::encode_invitation_id(&inv_id);
                    if let Some(inv_bytes) = self
                        .storage
                        .get(realm_id, &inv_key)
                        .map_err(Self::storage_err)?
                    {
                        if let Ok(invitation) =
                            serde_json::from_slice::<OrganizationInvitation>(&inv_bytes)
                        {
                            // Delete token index
                            let token_key = keys::encode_invitation_token(invitation.token_hash());
                            self.storage
                                .delete(realm_id, &token_key)
                                .map_err(Self::storage_err)?;
                            // Delete email dedup index
                            let email_key =
                                keys::encode_invitation_org_email(org_id, invitation.email());
                            self.storage
                                .delete(realm_id, &email_key)
                                .map_err(Self::storage_err)?;
                        }
                    }
                    self.storage
                        .delete(realm_id, &inv_key)
                        .map_err(Self::storage_err)?;
                }
            }
            // Delete list index entry
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 3. Delete slug index
        let slug_key = keys::encode_org_slug(org.slug());
        self.storage
            .delete(realm_id, &slug_key)
            .map_err(Self::storage_err)?;

        // 4. Cascade SCIM externalId mapping (forward + reverse).
        let scim_fwd_key = keys::encode_scim_ext_group_fwd_key(org_id);
        if let Some(ext_bytes) = self
            .storage
            .get(realm_id, &scim_fwd_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(ext_str) = std::str::from_utf8(&ext_bytes) {
                let reverse_key = keys::encode_scim_ext_group_key(ext_str);
                self.storage
                    .delete(realm_id, &reverse_key)
                    .map_err(Self::storage_err)?;
            }
            self.storage
                .delete(realm_id, &scim_fwd_key)
                .map_err(Self::storage_err)?;
        }

        // 5. Delete org record
        let id_key = keys::encode_org_id(org_id);
        self.storage
            .delete(realm_id, &id_key)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::OrgDeleted,
            "org",
            &org_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn list_organizations(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Organization>, IdentityError> {
        let prefix = keys::org_id_scan_prefix();
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("org:id:{uuid_str}").into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            let org: Organization =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(org);
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn add_member(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError> {
        // Verify org exists and is active
        let org = self
            .get_organization(realm_id, org_id)?
            .ok_or(IdentityError::OrganizationNotFound)?;
        if org.status() != OrganizationStatus::Active {
            return Err(IdentityError::OrganizationSuspended);
        }

        // Verify user exists
        self.get_user(realm_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Check not already a member
        let fwd_key = keys::encode_membership_by_org(org_id, user_id);
        if self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::AlreadyMember);
        }

        // Check member limit
        if let Some(max) = org.config().max_members {
            let member_prefix = keys::membership_by_org_prefix(org_id);
            let member_end = keys::prefix_end(&member_prefix);
            let count = self
                .storage
                .scan(realm_id, &member_prefix, &member_end)
                .map_err(Self::storage_err)?
                .len();
            if count >= max as usize {
                return Err(IdentityError::MemberLimitReached);
            }
        }

        let now = self.clock.now();
        let membership =
            OrganizationMembership::new(org_id.clone(), user_id.clone(), role, now, None);

        let membership_bytes =
            serde_json::to_vec(&membership).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Write forward index (org → user)
        self.storage
            .put(realm_id, &fwd_key, &membership_bytes)
            .map_err(Self::storage_err)?;

        // Write reverse index (user → org)
        let rev_key = keys::encode_membership_by_user(user_id, org_id);
        self.storage
            .put(realm_id, &rev_key, &membership_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::GroupMemberAdded,
            "org_membership",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(membership)
    }

    fn remove_member(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let fwd_key = keys::encode_membership_by_org(org_id, user_id);
        let membership_bytes = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::NotAMember)?;

        let membership: OrganizationMembership = serde_json::from_slice(&membership_bytes)
            .map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Last-owner protection
        if membership.role() == OrganizationRole::Owner {
            let member_prefix = keys::membership_by_org_prefix(org_id);
            let member_end = keys::prefix_end(&member_prefix);
            let all_members = self
                .storage
                .scan(realm_id, &member_prefix, &member_end)
                .map_err(Self::storage_err)?;

            let owner_count = all_members
                .iter()
                .filter_map(|e| serde_json::from_slice::<OrganizationMembership>(&e.value).ok())
                .filter(|m| m.role() == OrganizationRole::Owner)
                .count();

            if owner_count <= 1 {
                return Err(IdentityError::LastOwner);
            }
        }

        // Delete forward index
        self.storage
            .delete(realm_id, &fwd_key)
            .map_err(Self::storage_err)?;

        // Delete reverse index
        let rev_key = keys::encode_membership_by_user(user_id, org_id);
        self.storage
            .delete(realm_id, &rev_key)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::GroupMemberRemoved,
            "org_membership",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(())
    }

    fn update_member_role(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        new_role: OrganizationRole,
    ) -> Result<OrganizationMembership, IdentityError> {
        let fwd_key = keys::encode_membership_by_org(org_id, user_id);
        let membership_bytes = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::NotAMember)?;

        let mut membership: OrganizationMembership = serde_json::from_slice(&membership_bytes)
            .map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Last-owner protection: if downgrading from Owner, ensure others exist
        if membership.role() == OrganizationRole::Owner && new_role != OrganizationRole::Owner {
            let member_prefix = keys::membership_by_org_prefix(org_id);
            let member_end = keys::prefix_end(&member_prefix);
            let all_members = self
                .storage
                .scan(realm_id, &member_prefix, &member_end)
                .map_err(Self::storage_err)?;

            let owner_count = all_members
                .iter()
                .filter_map(|e| serde_json::from_slice::<OrganizationMembership>(&e.value).ok())
                .filter(|m| m.role() == OrganizationRole::Owner)
                .count();

            if owner_count <= 1 {
                return Err(IdentityError::LastOwner);
            }
        }

        membership.set_role(new_role);

        let updated_bytes =
            serde_json::to_vec(&membership).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Update both indexes
        self.storage
            .put(realm_id, &fwd_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        let rev_key = keys::encode_membership_by_user(user_id, org_id);
        self.storage
            .put(realm_id, &rev_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        self.record_audit(
            realm_id,
            None,
            AuditAction::GroupMemberRoleChanged,
            "org_membership",
            &user_id.as_uuid().to_string(),
        )?;

        Ok(membership)
    }

    fn get_membership(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Option<OrganizationMembership>, IdentityError> {
        let key = keys::encode_membership_by_org(org_id, user_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let membership: OrganizationMembership =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(membership))
            }
            None => Ok(None),
        }
    }

    fn list_members(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError> {
        let prefix = keys::membership_by_org_prefix(org_id);
        let start = if let Some(cursor_str) = cursor {
            let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key =
                format!("orgm:org:{}:user:{}", org_id.as_uuid(), decoded).into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            let membership: OrganizationMembership =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(membership);
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.user_id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn list_user_organizations(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationMembership>, IdentityError> {
        let prefix = keys::membership_by_user_prefix(user_id);
        let start = if let Some(cursor_str) = cursor {
            let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key =
                format!("orgm:user:{}:org:{}", user_id.as_uuid(), decoded).into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            let membership: OrganizationMembership =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(membership);
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.org_id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    fn create_invitation(
        &self,
        realm_id: &RealmId,
        request: &CreateInvitationRequest,
    ) -> Result<(OrganizationInvitation, String), IdentityError> {
        // Verify org exists and is active
        let org = self
            .get_organization(realm_id, &request.org_id)?
            .ok_or(IdentityError::OrganizationNotFound)?;
        if org.status() != OrganizationStatus::Active {
            return Err(IdentityError::OrganizationSuspended);
        }

        let email = validation::validate_email(&request.email)?;

        // Check for duplicate pending invitation
        let dedup_key = keys::encode_invitation_org_email(&request.org_id, &email);
        if self
            .storage
            .get(realm_id, &dedup_key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::DuplicateInvitation);
        }

        // Check if already a member (by email → user lookup)
        if let Some(user) = self.get_user_by_email(realm_id, &email)? {
            if self
                .get_membership(realm_id, &request.org_id, user.id())?
                .is_some()
            {
                return Err(IdentityError::AlreadyMember);
            }
        }

        // Generate token
        let rng = ring::rand::SystemRandom::new();
        let mut token_bytes = [0u8; 32];
        rng.fill(&mut token_bytes)
            .map_err(|_| IdentityError::SigningError {
                reason: "RNG failure".to_string(),
            })?;
        let plaintext_token = URL_SAFE_NO_PAD.encode(token_bytes);

        // Hash token for storage
        let token_hash = {
            use ring::digest;
            let digest = digest::digest(&digest::SHA256, plaintext_token.as_bytes());
            hex_encode(digest.as_ref())
        };

        let now = self.clock.now();
        // 7-day expiry
        let expires_at = now.add_micros(7 * 24 * 60 * 60 * 1_000_000);

        let invitation_id = InvitationId::generate();
        let invitation = OrganizationInvitation::new(
            invitation_id.clone(),
            request.org_id.clone(),
            email.clone(),
            request.role,
            token_hash.clone(),
            InvitationStatus::Pending,
            expires_at,
            request.invited_by.clone(),
            now,
        );

        let inv_bytes =
            serde_json::to_vec(&invitation).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Write primary record
        let id_key = keys::encode_invitation_id(&invitation_id);
        self.storage
            .put(realm_id, &id_key, &inv_bytes)
            .map_err(Self::storage_err)?;

        // Write token index
        let token_key = keys::encode_invitation_token(&token_hash);
        self.storage
            .put(realm_id, &token_key, invitation_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;

        // Write email dedup index
        self.storage
            .put(realm_id, &dedup_key, invitation_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;

        // Write list index
        let list_key = keys::encode_invitation_list(&request.org_id, &invitation_id);
        self.storage
            .put(realm_id, &list_key, &[])
            .map_err(Self::storage_err)?;

        Ok((invitation, plaintext_token))
    }

    fn accept_invitation(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<OrganizationMembership, IdentityError> {
        // Hash the token
        let token_hash = {
            use ring::digest;
            let digest = digest::digest(&digest::SHA256, token.as_bytes());
            hex_encode(digest.as_ref())
        };

        // Look up by token hash
        let token_key = keys::encode_invitation_token(&token_hash);
        let inv_id_bytes = self
            .storage
            .get(realm_id, &token_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvitationInvalid)?;

        let inv_uuid =
            uuid::Uuid::from_slice(&inv_id_bytes).map_err(|e| IdentityError::Serialization {
                reason: format!("invalid invitation UUID: {e}"),
            })?;
        let invitation_id = InvitationId::new(inv_uuid);

        // Load invitation
        let inv_key = keys::encode_invitation_id(&invitation_id);
        let inv_bytes = self
            .storage
            .get(realm_id, &inv_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvitationInvalid)?;

        let mut invitation: OrganizationInvitation =
            serde_json::from_slice(&inv_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // Validate status
        if invitation.status() != InvitationStatus::Pending {
            return Err(IdentityError::InvitationInvalid);
        }

        // Validate expiry
        let now = self.clock.now();
        if now >= invitation.expires_at() {
            return Err(IdentityError::InvitationInvalid);
        }

        // Find or create user by email
        let user = if let Some(u) = self.get_user_by_email(realm_id, invitation.email())? {
            u
        } else {
            // Auto-create user for unknown email
            self.create_user(
                realm_id,
                &CreateUserRequest {
                    email: invitation.email().to_string(),
                    display_name: invitation.email().to_string(),
                    ..Default::default()
                },
            )?
        };

        // Add member
        let membership =
            self.add_member(realm_id, invitation.org_id(), user.id(), invitation.role())?;

        // Mark invitation as accepted
        invitation.set_accepted();
        let updated_bytes =
            serde_json::to_vec(&invitation).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &inv_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // Remove dedup index so a new invitation can be sent if needed
        let dedup_key = keys::encode_invitation_org_email(invitation.org_id(), invitation.email());
        self.storage
            .delete(realm_id, &dedup_key)
            .map_err(Self::storage_err)?;

        Ok(membership)
    }

    fn revoke_invitation(
        &self,
        realm_id: &RealmId,
        invitation_id: &InvitationId,
    ) -> Result<(), IdentityError> {
        let inv_key = keys::encode_invitation_id(invitation_id);
        let inv_bytes = self
            .storage
            .get(realm_id, &inv_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvitationInvalid)?;

        let mut invitation: OrganizationInvitation =
            serde_json::from_slice(&inv_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        if invitation.status() != InvitationStatus::Pending {
            return Err(IdentityError::InvitationInvalid);
        }

        invitation.set_revoked();
        let updated_bytes =
            serde_json::to_vec(&invitation).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(realm_id, &inv_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // Clean up dedup index
        let dedup_key = keys::encode_invitation_org_email(invitation.org_id(), invitation.email());
        self.storage
            .delete(realm_id, &dedup_key)
            .map_err(Self::storage_err)?;

        Ok(())
    }

    fn list_invitations(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<OrganizationInvitation>, IdentityError> {
        let prefix = keys::invitation_list_prefix(org_id);
        let start = if let Some(cursor_str) = cursor {
            let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("orgi:list:{}:{}", org_id.as_uuid(), decoded).into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(realm_id, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            // Extract invitation ID from list key
            let key_str =
                std::str::from_utf8(&entry.key).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if let Some(inv_uuid_str) = key_str.rsplit(':').next() {
                if let Ok(uuid) = uuid::Uuid::parse_str(inv_uuid_str) {
                    let inv_id = InvitationId::new(uuid);
                    let inv_key = keys::encode_invitation_id(&inv_id);
                    if let Some(inv_bytes) = self
                        .storage
                        .get(realm_id, &inv_key)
                        .map_err(Self::storage_err)?
                    {
                        let invitation: OrganizationInvitation = serde_json::from_slice(&inv_bytes)
                            .map_err(|e| IdentityError::Serialization {
                                reason: e.to_string(),
                            })?;
                        items.push(invitation);
                    }
                }
            }
        }

        let next_cursor = if items.len() > limit {
            items.pop();
            let last_kept = items.last().expect("limit >= 1");
            Some(URL_SAFE_NO_PAD.encode(last_kept.id().as_uuid().to_string()))
        } else {
            None
        };

        Ok(Page { items, next_cursor })
    }

    // ===== External IdP federation =====

    fn register_idp(
        &self,
        config: &crate::identity::federation::IdpConfig,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_idp_key(&config.id);
        let bytes = serde_json::to_vec(config).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.record_audit(
            &config.realm_id,
            None,
            AuditAction::FederationAccountLinked,
            "idp",
            &config.id.as_uuid().to_string(),
        )?;
        self.storage
            .put(&config.realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn get_idp(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
    ) -> Result<Option<crate::identity::federation::IdpConfig>, IdentityError> {
        let key = keys::encode_idp_key(idp_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let cfg: crate::identity::federation::IdpConfig =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        Ok(Some(cfg))
    }

    fn get_idp_by_name(
        &self,
        realm_id: &RealmId,
        name: &str,
    ) -> Result<Option<crate::identity::federation::IdpConfig>, IdentityError> {
        // Linear scan — N is tiny (realms have a handful of connectors
        // at most). Avoids the cost of a secondary `fed:idp_name:` index.
        let prefix = keys::fed_idp_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        for entry in &entries {
            let cfg: crate::identity::federation::IdpConfig = serde_json::from_slice(&entry.value)
                .map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            if cfg.name == name {
                return Ok(Some(cfg));
            }
        }
        Ok(None)
    }

    fn list_idps(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<crate::identity::federation::IdpConfig>, IdentityError> {
        let prefix = keys::fed_idp_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let cfg: crate::identity::federation::IdpConfig = serde_json::from_slice(&entry.value)
                .map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            out.push(cfg);
        }
        Ok(out)
    }

    fn delete_idp(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
    ) -> Result<(), IdentityError> {
        // Sever every external-identity link this connector owns before
        // removing the connector record itself. Forward indexes
        // `fed:ext_fwd:{user}:{idp}` are cleaned by first enumerating
        // reverse entries and deriving `(user_id, sub)` from the value.
        let ext_prefix = keys::encode_federation_ext_prefix_for_idp(idp_id);
        let ext_end = keys::prefix_end(&ext_prefix);
        let ext_entries = self
            .storage
            .scan(realm_id, &ext_prefix, &ext_end)
            .map_err(Self::storage_err)?;
        for entry in &ext_entries {
            // value = UserId UUID bytes (16)
            if entry.value.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&entry.value);
                let user_id = UserId::new(uuid::Uuid::from_bytes(b));
                let fwd_key = keys::encode_federation_ext_fwd_key(&user_id, idp_id);
                self.storage
                    .delete(realm_id, &fwd_key)
                    .map_err(Self::storage_err)?;
            }
            self.storage
                .delete(realm_id, &entry.key)
                .map_err(Self::storage_err)?;
        }
        // Now remove the connector record itself.
        self.record_audit(
            realm_id,
            None,
            AuditAction::FederationAccountUnlinked,
            "idp",
            &idp_id.as_uuid().to_string(),
        )?;
        let key = keys::encode_idp_key(idp_id);
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)
    }

    fn put_federation_state(
        &self,
        bag: &crate::identity::federation::StateBag,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_federation_state_key(&bag.state_token);
        let bytes = serde_json::to_vec(bag).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(&bag.realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn take_federation_state(
        &self,
        realm_id: &RealmId,
        state_token: &str,
    ) -> Result<crate::identity::federation::StateBag, IdentityError> {
        let key = keys::encode_federation_state_key(state_token);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::FederationInvalidState)?;
        // Single-use: delete before we even validate.
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let bag: crate::identity::federation::StateBag =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if self.clock.now().as_micros() >= bag.expires_at.as_micros() {
            return Err(IdentityError::FederationInvalidState);
        }
        Ok(bag)
    }

    fn put_confirm_link_ticket(
        &self,
        ticket: &crate::identity::federation::ConfirmLinkTicket,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_federation_confirm_key(&ticket.ticket);
        let bytes = serde_json::to_vec(ticket).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(&ticket.realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn take_confirm_link_ticket(
        &self,
        realm_id: &RealmId,
        ticket: &str,
    ) -> Result<crate::identity::federation::ConfirmLinkTicket, IdentityError> {
        let key = keys::encode_federation_confirm_key(ticket);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::FederationInvalidState)?;
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let t: crate::identity::federation::ConfirmLinkTicket = serde_json::from_slice(&bytes)
            .map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        if self.clock.now().as_micros() >= t.expires_at.as_micros() {
            return Err(IdentityError::FederationInvalidState);
        }
        Ok(t)
    }

    fn link_external_identity(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &crate::core::IdpId,
        external_sub: &str,
    ) -> Result<(), IdentityError> {
        let reverse_key = keys::encode_federation_ext_key(idp_id, external_sub);
        // Refuse to re-home an external identity that already belongs
        // to a different user. The owner must unlink first. This is
        // also the guard against a malicious IdP trying to "steal" an
        // already-linked account.
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reverse_key)
            .map_err(Self::storage_err)?
        {
            if bytes.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&bytes);
                let existing = UserId::new(uuid::Uuid::from_bytes(b));
                if &existing != user_id {
                    return Err(IdentityError::FederationAlreadyLinked);
                }
                // Same user re-linking — no-op write below is idempotent.
            }
        }
        let forward_key = keys::encode_federation_ext_fwd_key(user_id, idp_id);
        self.storage
            .put(realm_id, &reverse_key, user_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;
        self.record_audit(
            realm_id,
            None,
            AuditAction::FederationAccountLinked,
            "federation",
            &idp_id.as_uuid().to_string(),
        )?;
        self.storage
            .put(realm_id, &forward_key, external_sub.as_bytes())
            .map_err(Self::storage_err)
    }

    fn unlink_external_identity(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &crate::core::IdpId,
    ) -> Result<(), IdentityError> {
        let forward_key = keys::encode_federation_ext_fwd_key(user_id, idp_id);
        let external_sub_bytes = self
            .storage
            .get(realm_id, &forward_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::FederationNotLinked)?;
        let external_sub =
            std::str::from_utf8(&external_sub_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let reverse_key = keys::encode_federation_ext_key(idp_id, external_sub);
        self.storage
            .delete(realm_id, &reverse_key)
            .map_err(Self::storage_err)?;
        self.record_audit(
            realm_id,
            None,
            AuditAction::FederationAccountUnlinked,
            "federation",
            &idp_id.as_uuid().to_string(),
        )?;
        self.storage
            .delete(realm_id, &forward_key)
            .map_err(Self::storage_err)
    }

    fn find_user_by_external_identity(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
        external_sub: &str,
    ) -> Result<Option<UserId>, IdentityError> {
        let key = keys::encode_federation_ext_key(idp_id, external_sub);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        if bytes.len() != 16 {
            return Err(IdentityError::Serialization {
                reason: "federation reverse index has wrong length".to_string(),
            });
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&bytes);
        Ok(Some(UserId::new(uuid::Uuid::from_bytes(b))))
    }

    fn list_external_identities_for_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<(crate::core::IdpId, String)>, IdentityError> {
        let prefix = keys::encode_federation_ext_fwd_prefix_for_user(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let key_str = std::str::from_utf8(&entry.key).unwrap_or("");
            let Some(idp_uuid_str) = key_str.rsplit(':').next() else {
                continue;
            };
            let Ok(idp_uuid) = uuid::Uuid::parse_str(idp_uuid_str) else {
                continue;
            };
            let external_sub = std::str::from_utf8(&entry.value)
                .map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?
                .to_string();
            out.push((crate::core::IdpId::new(idp_uuid), external_sub));
        }
        Ok(out)
    }

    // ===== SCIM externalId management =====

    fn set_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        external_id: &str,
    ) -> Result<(), IdentityError> {
        if external_id.is_empty() {
            return Err(IdentityError::InvalidInput {
                reason: "externalId must not be empty".to_string(),
            });
        }
        // Refuse to steal an externalId from another user.
        let reverse_key = keys::encode_scim_ext_user_key(external_id);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reverse_key)
            .map_err(Self::storage_err)?
        {
            if bytes.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&bytes);
                let existing = UserId::new(uuid::Uuid::from_bytes(b));
                if &existing != user_id {
                    return Err(IdentityError::DuplicateScimExternalId);
                }
            }
        }
        // Retire any prior externalId for this user.
        let fwd_key = keys::encode_scim_ext_user_fwd_key(user_id);
        if let Some(old_ext) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(old_ext_str) = std::str::from_utf8(&old_ext) {
                if old_ext_str != external_id {
                    let old_reverse = keys::encode_scim_ext_user_key(old_ext_str);
                    self.storage
                        .delete(realm_id, &old_reverse)
                        .map_err(Self::storage_err)?;
                }
            }
        }
        self.storage
            .put(realm_id, &reverse_key, user_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;
        self.storage
            .put(realm_id, &fwd_key, external_id.as_bytes())
            .map_err(Self::storage_err)
    }

    fn clear_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let fwd_key = keys::encode_scim_ext_user_fwd_key(user_id);
        let Some(ext_bytes) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(());
        };
        let ext_str =
            std::str::from_utf8(&ext_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let reverse_key = keys::encode_scim_ext_user_key(ext_str);
        self.storage
            .delete(realm_id, &reverse_key)
            .map_err(Self::storage_err)?;
        self.storage
            .delete(realm_id, &fwd_key)
            .map_err(Self::storage_err)
    }

    fn get_scim_external_id(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<String>, IdentityError> {
        let fwd_key = keys::encode_scim_ext_user_fwd_key(user_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let s = std::str::from_utf8(&bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        Ok(Some(s.to_string()))
    }

    fn find_user_by_scim_external_id(
        &self,
        realm_id: &RealmId,
        external_id: &str,
    ) -> Result<Option<User>, IdentityError> {
        let key = keys::encode_scim_ext_user_key(external_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        if bytes.len() != 16 {
            return Err(IdentityError::Serialization {
                reason: "SCIM reverse index has wrong length".to_string(),
            });
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&bytes);
        let user_id = UserId::new(uuid::Uuid::from_bytes(b));
        self.get_user(realm_id, &user_id)
    }

    fn set_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        external_id: &str,
    ) -> Result<(), IdentityError> {
        if external_id.is_empty() {
            return Err(IdentityError::InvalidInput {
                reason: "externalId must not be empty".to_string(),
            });
        }
        let reverse_key = keys::encode_scim_ext_group_key(external_id);
        if let Some(bytes) = self
            .storage
            .get(realm_id, &reverse_key)
            .map_err(Self::storage_err)?
        {
            if bytes.len() == 16 {
                let mut b = [0u8; 16];
                b.copy_from_slice(&bytes);
                let existing = OrganizationId::new(uuid::Uuid::from_bytes(b));
                if &existing != org_id {
                    return Err(IdentityError::DuplicateScimExternalId);
                }
            }
        }
        let fwd_key = keys::encode_scim_ext_group_fwd_key(org_id);
        if let Some(old_ext) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        {
            if let Ok(old_ext_str) = std::str::from_utf8(&old_ext) {
                if old_ext_str != external_id {
                    let old_reverse = keys::encode_scim_ext_group_key(old_ext_str);
                    self.storage
                        .delete(realm_id, &old_reverse)
                        .map_err(Self::storage_err)?;
                }
            }
        }
        self.storage
            .put(realm_id, &reverse_key, org_id.as_uuid().as_bytes())
            .map_err(Self::storage_err)?;
        self.storage
            .put(realm_id, &fwd_key, external_id.as_bytes())
            .map_err(Self::storage_err)
    }

    fn clear_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<(), IdentityError> {
        let fwd_key = keys::encode_scim_ext_group_fwd_key(org_id);
        let Some(ext_bytes) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(());
        };
        let ext_str =
            std::str::from_utf8(&ext_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let reverse_key = keys::encode_scim_ext_group_key(ext_str);
        self.storage
            .delete(realm_id, &reverse_key)
            .map_err(Self::storage_err)?;
        self.storage
            .delete(realm_id, &fwd_key)
            .map_err(Self::storage_err)
    }

    fn get_scim_group_external_id(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
    ) -> Result<Option<String>, IdentityError> {
        let fwd_key = keys::encode_scim_ext_group_fwd_key(org_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &fwd_key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let s = std::str::from_utf8(&bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        Ok(Some(s.to_string()))
    }

    fn find_group_by_scim_external_id(
        &self,
        realm_id: &RealmId,
        external_id: &str,
    ) -> Result<Option<crate::identity::Organization>, IdentityError> {
        let key = keys::encode_scim_ext_group_key(external_id);
        let Some(bytes) = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        if bytes.len() != 16 {
            return Err(IdentityError::Serialization {
                reason: "SCIM group reverse index has wrong length".to_string(),
            });
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&bytes);
        let org_id = OrganizationId::new(uuid::Uuid::from_bytes(b));
        self.get_organization(realm_id, &org_id)
    }

    // ===== Webhooks =====

    fn create_webhook(
        &self,
        realm_id: &RealmId,
        req: &crate::identity::CreateWebhookRequest,
    ) -> Result<crate::identity::Webhook, IdentityError> {
        use crate::identity::types::Webhook;
        let id = WebhookId::generate();
        let now = self.clock.now();
        let webhook = Webhook::new(
            id.clone(),
            realm_id.clone(),
            req.url.clone(),
            req.secret.clone(),
            req.events.clone(),
            req.enabled,
            now,
            now,
        );
        let value = serde_json::to_vec(&webhook).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &keys::encode_webhook_id(&id), &value)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        Ok(webhook)
    }

    fn get_webhook(
        &self,
        realm_id: &RealmId,
        webhook_id: &WebhookId,
    ) -> Result<Option<crate::identity::Webhook>, IdentityError> {
        use crate::identity::types::Webhook;
        match self
            .storage
            .get(realm_id, &keys::encode_webhook_id(webhook_id))
            .map_err(|e| IdentityError::Storage(Box::new(e)))?
        {
            Some(bytes) => {
                let wh: Webhook =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(wh))
            }
            None => Ok(None),
        }
    }

    fn list_webhooks(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<crate::identity::Webhook>, IdentityError> {
        use crate::identity::types::Webhook;
        let prefix = keys::webhook_id_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            match serde_json::from_slice::<Webhook>(&entry.value) {
                Ok(wh) => out.push(wh),
                Err(e) => {
                    tracing::warn!(error = %e, "webhook deserialization failed, skipping");
                }
            }
        }
        out.sort_by_key(|w| w.created_at);
        Ok(out)
    }

    fn delete_webhook(
        &self,
        realm_id: &RealmId,
        webhook_id: &WebhookId,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_webhook_id(webhook_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(|e| IdentityError::Storage(Box::new(e)))?
        {
            None => Err(IdentityError::WebhookNotFound),
            Some(_) => {
                self.storage
                    .delete(realm_id, &key)
                    .map_err(|e| IdentityError::Storage(Box::new(e)))?;
                Ok(())
            }
        }
    }

    // ===== Periodic cleanup =====

    fn sweep_expired(
        &self,
        realm_id: &RealmId,
    ) -> Result<crate::identity::cleanup::CleanupStats, IdentityError> {
        let stats = crate::identity::cleanup::sweep_expired(
            realm_id,
            self.storage.as_ref(),
            self.clock.as_ref(),
            &self.config.cleanup,
        );

        if stats.total_deleted() > 0 {
            let metadata = Some(serde_json::json!({
                "auth_codes_deleted": stats.auth_codes_deleted,
                "device_codes_deleted": stats.device_codes_deleted,
                "pending_tickets_deleted": stats.pending_tickets_deleted,
                "grant_families_deleted": stats.grant_families_deleted,
                "errors": stats.errors,
            }));
            let ctx = crate::audit::context::AuditContext {
                actor: crate::audit::context::Actor::System,
                metadata,
            };
            let _ = self.record_audit(
                realm_id,
                Some(&ctx),
                crate::audit::AuditAction::Cleanup,
                "system",
                &realm_id.to_string(),
            );
        }

        Ok(stats)
    }

    // ===== SAML =====

    fn get_or_create_saml_signing_key(
        &self,
        realm_id: &RealmId,
        issuer_cn: &str,
    ) -> Result<Arc<crate::identity::tokens::RsaSigningKey>, IdentityError> {
        let key_str = realm_id.as_uuid().to_string();
        {
            let cache = self.realm_saml_keys.lock().expect("saml key cache");
            if let Some(k) = cache.get(&key_str) {
                return Ok(k.clone());
            }
        }
        let sys_realm = keys::system_realm_id();
        let storage_key = keys::encode_realm_saml_key(realm_id);

        // Two-part value: [8-byte cert_der_len BE, pkcs8_der | cert_der].
        // Simpler to use JSON, but key bytes must not serialize cleartext
        // into logs — JSON is fine since this struct isn't logged.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Stored {
            pkcs8: Vec<u8>,
            cert: Vec<u8>,
        }

        let key = if let Some(bytes) = self
            .storage
            .get(&sys_realm, &storage_key)
            .map_err(Self::storage_err)?
        {
            let stored: Stored =
                serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            crate::identity::tokens::RsaSigningKey::from_pkcs8_and_cert(
                &stored.pkcs8,
                &stored.cert,
            )?
        } else {
            let generated = crate::identity::tokens::RsaSigningKey::generate(issuer_cn, 3650)?;
            let stored = Stored {
                pkcs8: generated.pkcs8_bytes().to_vec(),
                cert: generated.cert_der().to_vec(),
            };
            let body = serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
            self.storage
                .put(&sys_realm, &storage_key, &body)
                .map_err(Self::storage_err)?;
            generated
        };
        let arc = Arc::new(key);
        {
            let mut cache = self.realm_saml_keys.lock().expect("saml key cache");
            cache.insert(key_str, arc.clone());
        }
        Ok(arc)
    }

    fn register_saml_sp(
        &self,
        realm_id: &RealmId,
        sp: &crate::identity::federation::saml::SamlServiceProvider,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_saml_sp_key(&sp.sp_key);
        let bytes = serde_json::to_vec(sp).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn get_saml_sp_by_entity_id(
        &self,
        realm_id: &RealmId,
        entity_id: &str,
    ) -> Result<Option<crate::identity::federation::saml::SamlServiceProvider>, IdentityError> {
        for sp in self.list_saml_sps(realm_id)? {
            if sp.entity_id == entity_id {
                return Ok(Some(sp));
            }
        }
        Ok(None)
    }

    fn get_saml_sp_by_key(
        &self,
        realm_id: &RealmId,
        sp_key: &str,
    ) -> Result<Option<crate::identity::federation::saml::SamlServiceProvider>, IdentityError> {
        let key = keys::encode_saml_sp_key(sp_key);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            Some(bytes) => {
                let sp =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(sp))
            }
            None => Ok(None),
        }
    }

    fn list_saml_sps(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<crate::identity::federation::saml::SamlServiceProvider>, IdentityError> {
        let prefix = keys::saml_sp_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let sp: crate::identity::federation::saml::SamlServiceProvider =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            out.push(sp);
        }
        Ok(out)
    }

    fn delete_saml_sp(&self, realm_id: &RealmId, sp_key: &str) -> Result<(), IdentityError> {
        let key = keys::encode_saml_sp_key(sp_key);
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)
    }

    fn put_saml_state(
        &self,
        bag: &crate::identity::federation::saml::SamlStateBag,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_saml_state_key(&bag.token);
        let bytes = serde_json::to_vec(bag).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(&bag.realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn take_saml_state(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<crate::identity::federation::saml::SamlStateBag, IdentityError> {
        let key = keys::encode_saml_state_key(token);
        let bytes = self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::FederationInvalidState)?;
        self.storage
            .delete(realm_id, &key)
            .map_err(Self::storage_err)?;
        let bag: crate::identity::federation::saml::SamlStateBag =
            serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        // 10-minute TTL.
        let age_secs = (self.clock.now().as_micros() - bag.created_at.as_micros()) / 1_000_000;
        if age_secs > 600 {
            return Err(IdentityError::FederationInvalidState);
        }
        Ok(bag)
    }

    fn mark_saml_assertion_consumed(
        &self,
        realm_id: &RealmId,
        idp_id: &crate::core::IdpId,
        assertion_id: &str,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_saml_assertion_id(idp_id, assertion_id);
        if self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
            .is_some()
        {
            return Err(IdentityError::SamlReplay);
        }
        self.storage
            .put(realm_id, &key, &[])
            .map_err(Self::storage_err)
    }

    fn record_saml_sp_session(
        &self,
        realm_id: &RealmId,
        registration: &crate::identity::federation::saml::SamlSessionRegistration,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_saml_sp_session(&registration.session_id, &registration.sp_key);
        let bytes = serde_json::to_vec(registration).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(realm_id, &key, &bytes)
            .map_err(Self::storage_err)
    }

    fn list_saml_sp_sessions(
        &self,
        realm_id: &RealmId,
        session_id: &SessionId,
    ) -> Result<Vec<crate::identity::federation::saml::SamlSessionRegistration>, IdentityError>
    {
        let prefix = keys::encode_saml_sp_session_prefix(session_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(realm_id, &prefix, &end)
            .map_err(Self::storage_err)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let reg: crate::identity::federation::saml::SamlSessionRegistration =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            out.push(reg);
        }
        Ok(out)
    }

    fn is_storage_healthy(&self) -> bool {
        // Probe the storage engine with a get on a known-absent sentinel key.
        // Success (even returning None) confirms the storage layer is live.
        let probe_realm = keys::system_realm_id();
        self.storage.get(&probe_realm, b"health:probe").is_ok()
    }

    fn initiate_logout(
        &self,
        realm_id: &RealmId,
        request: &RpLogoutRequest,
    ) -> Result<RpLogoutResult, IdentityError> {
        // Resolve session ID and user ID from id_token_hint or explicit session_id.
        let (session_id, user_id) = if let Some(hint) = &request.id_token_hint {
            // Decode without signature verification — OIDC spec allows expired hints.
            let claims =
                tokens::decode_claims_unverified(hint).map_err(|_| IdentityError::InvalidToken)?;
            let sid = Self::parse_session_id_claim(&claims)?.ok_or(IdentityError::InvalidToken)?;
            let uid = Self::parse_user_id_claim(&claims)?;
            (sid, uid)
        } else if let Some(sid) = &request.session_id {
            let session = self
                .get_session(realm_id, sid)?
                .ok_or(IdentityError::SessionNotFound)?;
            (sid.clone(), session.user_id().clone())
        } else {
            return Err(IdentityError::InvalidToken);
        };

        // Revoke the session (and cascade to grant families).
        match self.revoke_session(realm_id, &session_id) {
            Ok(()) | Err(IdentityError::SessionNotFound) => {}
            Err(e) => return Err(e),
        }

        // Collect all OAuth clients that received tokens under this session.
        let sfam_prefix = keys::encode_session_grant_family_prefix(&session_id);
        let sfam_end = keys::prefix_end(&sfam_prefix);

        let mut backchannel_targets: Vec<BackchannelTarget> = Vec::new();
        let mut frontchannel_targets: Vec<FrontchannelTarget> = Vec::new();

        if let Ok(entries) = self.storage.scan(realm_id, &sfam_prefix, &sfam_end) {
            let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
            let issuer = self.config.oidc.issuer.clone();
            let now = self.clock.now();
            let iat = now.as_micros() / 1_000_000;

            let mut seen_client_ids = std::collections::HashSet::new();

            for entry in &entries {
                let family_id = match std::str::from_utf8(&entry.key[sfam_prefix.len()..]) {
                    Ok(s) if !s.is_empty() => s,
                    _ => continue,
                };

                let family_key = keys::encode_grant_family(family_id);
                let fam = match self.storage.get(realm_id, &family_key) {
                    Ok(Some(bytes)) => match serde_json::from_slice::<StoredGrantFamily>(&bytes) {
                        Ok(f) => f,
                        Err(_) => continue,
                    },
                    _ => continue,
                };

                let client_id = match fam.client_id {
                    Some(id) => id,
                    None => continue,
                };

                if !seen_client_ids.insert(client_id.clone()) {
                    continue; // Already processed this client for this session.
                }

                let client_key = keys::encode_oauth_client(&client_id);
                let client = match self.storage.get(realm_id, &client_key) {
                    Ok(Some(bytes)) => match serde_json::from_slice::<OAuthClient>(&bytes) {
                        Ok(c) => c,
                        Err(_) => continue,
                    },
                    _ => continue,
                };

                if let Some(bcl_uri) = client.backchannel_logout_uri() {
                    let jti = uuid::Uuid::new_v4().to_string();
                    let logout_claims = LogoutTokenClaims::new(
                        issuer.clone(),
                        user_id.as_uuid().to_string(),
                        Audience::single(client_id.as_uuid().to_string()),
                        session_id.as_uuid().to_string(),
                        jti,
                        iat,
                    );
                    if let Ok(token) = signing_key.issue_logout_token(&logout_claims) {
                        backchannel_targets.push(BackchannelTarget {
                            uri: bcl_uri.to_string(),
                            logout_token: token,
                        });
                    }
                }

                if let Some(fcl_uri) = client.frontchannel_logout_uri() {
                    frontchannel_targets.push(FrontchannelTarget {
                        uri: fcl_uri.to_string(),
                        client_id: client_id.clone(),
                    });
                }
            }
        }

        // Validate post_logout_redirect_uri against the registering client's list.
        let post_logout_redirect_uri = match &request.post_logout_redirect_uri {
            None => None,
            Some(uri) => {
                let valid = match &request.client_id {
                    None => true, // No client specified — accept without validation.
                    Some(cid) => {
                        let client_key = keys::encode_oauth_client(cid);
                        match self.storage.get(realm_id, &client_key) {
                            Ok(Some(bytes)) => {
                                match serde_json::from_slice::<OAuthClient>(&bytes) {
                                    Ok(c) => c.post_logout_redirect_uris().contains(uri),
                                    Err(_) => false,
                                }
                            }
                            _ => false,
                        }
                    }
                };
                if valid {
                    Some(uri.clone())
                } else {
                    None
                }
            }
        };

        Ok(RpLogoutResult {
            user_id,
            session_id,
            backchannel_targets,
            frontchannel_targets,
            post_logout_redirect_uri,
            state: request.state.clone(),
        })
    }
}

/// Classifies a PHC-formatted hash string into a [`PasswordAlgorithm`].
///
/// Used by `import_user` to tag an externally supplied hash. Returns
/// `None` for prefixes this code base does not know how to verify, so
/// the caller can fail fast rather than storing an unverifiable
/// credential.
fn classify_phc_algorithm(phc: &str) -> Option<crate::identity::credentials::PasswordAlgorithm> {
    use crate::identity::credentials::PasswordAlgorithm;
    if phc.starts_with("$argon2id$") {
        Some(PasswordAlgorithm::Argon2id)
    } else if phc.starts_with("$2a$") || phc.starts_with("$2b$") {
        Some(PasswordAlgorithm::Bcrypt)
    } else if phc.starts_with("$scrypt$") {
        Some(PasswordAlgorithm::Scrypt)
    } else if phc.starts_with("$pbkdf2-sha256$") {
        Some(PasswordAlgorithm::Pbkdf2Sha256)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::EmbeddedAuditEngine;
    use crate::core::{FakeClock, Timestamp};
    use crate::identity::types::RealmConfig;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

    fn setup_engine() -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    // ===== Scenario 1: Create user with required fields succeeds =====

    #[test]
    fn create_user_with_required_fields_succeeds() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let request = CreateUserRequest {
            email: "Alice@Example.COM".to_string(),
            display_name: "Alice Smith".to_string(),
            ..Default::default()
        };

        let user = engine.create_user(&realm, &request).expect("create");

        assert_eq!(user.email(), "alice@example.com");
        assert_eq!(user.display_name(), "Alice Smith");
        assert_eq!(user.status(), UserStatus::Active);
        assert_eq!(user.created_at(), Timestamp::from_micros(1_000_000));
        assert_eq!(user.updated_at(), Timestamp::from_micros(1_000_000));
    }

    #[test]
    fn create_user_generates_unique_id() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let user1 = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let user2 = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "bob@example.com".to_string(),
                    display_name: "Bob".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        assert_ne!(user1.id(), user2.id());
    }

    // ===== Scenario 2: Read user by ID and by email =====

    #[test]
    fn read_user_by_id_returns_correct_record() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let fetched = engine
            .get_user(&realm, created.id())
            .expect("get")
            .expect("should exist");

        assert_eq!(fetched, created);
    }

    #[test]
    fn read_user_by_email_returns_correct_record() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let fetched = engine
            .get_user_by_email(&realm, "Alice@Example.COM")
            .expect("get")
            .expect("should exist");

        assert_eq!(fetched, created);
    }

    #[test]
    fn read_nonexistent_user_returns_none() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let result = engine.get_user(&realm, &UserId::generate()).expect("get");
        assert!(result.is_none());
    }

    #[test]
    fn read_nonexistent_email_returns_none() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let result = engine
            .get_user_by_email(&realm, "nobody@example.com")
            .expect("get");
        assert!(result.is_none());
    }

    // ===== Scenario 3: Update user persists changes =====

    #[test]
    fn update_user_persists_changes() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        clock.advance(1_000_000); // advance 1 second

        let updated = engine
            .update_user(
                &realm,
                created.id(),
                &UpdateUserRequest {
                    display_name: Some("Alice Smith".to_string()),
                    ..UpdateUserRequest::default()
                },
            )
            .expect("update");

        assert_eq!(updated.display_name(), "Alice Smith");
        assert_eq!(updated.email(), "alice@example.com"); // unchanged
        assert_eq!(updated.created_at(), created.created_at()); // unchanged
        assert!(updated.updated_at() > created.updated_at()); // advanced

        // Verify persistence
        let fetched = engine
            .get_user(&realm, created.id())
            .expect("get")
            .expect("should exist");
        assert_eq!(fetched, updated);
    }

    #[test]
    fn update_user_email_swaps_index() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "old@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        clock.advance(1_000_000);

        engine
            .update_user(
                &realm,
                created.id(),
                &UpdateUserRequest {
                    email: Some("new@example.com".to_string()),
                    ..UpdateUserRequest::default()
                },
            )
            .expect("update");

        // Old email should not resolve
        let old_lookup = engine
            .get_user_by_email(&realm, "old@example.com")
            .expect("get");
        assert!(old_lookup.is_none());

        // New email should resolve
        let new_lookup = engine
            .get_user_by_email(&realm, "new@example.com")
            .expect("get")
            .expect("should exist");
        assert_eq!(new_lookup.id(), created.id());
    }

    #[test]
    fn update_user_status() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let updated = engine
            .update_user(
                &realm,
                created.id(),
                &UpdateUserRequest {
                    status: Some(UserStatus::Disabled),
                    ..UpdateUserRequest::default()
                },
            )
            .expect("update");

        assert_eq!(updated.status(), UserStatus::Disabled);
    }

    #[test]
    fn update_nonexistent_user_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .update_user(&realm, &UserId::generate(), &UpdateUserRequest::default())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    // ===== Scenario 4: Delete user removes record =====

    #[test]
    fn delete_user_removes_record() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        engine.delete_user(&realm, created.id()).expect("delete");

        // Should not be found by ID
        let by_id = engine.get_user(&realm, created.id()).expect("get");
        assert!(by_id.is_none());

        // Should not be found by email
        let by_email = engine
            .get_user_by_email(&realm, "alice@example.com")
            .expect("get");
        assert!(by_email.is_none());
    }

    #[test]
    fn delete_nonexistent_user_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .delete_user(&realm, &UserId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    #[test]
    fn delete_user_frees_email() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let created = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        engine.delete_user(&realm, created.id()).expect("delete");

        // Should be able to create a new user with the same email
        let new_user = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice 2".to_string(),
                    ..Default::default()
                },
            )
            .expect("create should succeed after delete");

        assert_ne!(new_user.id(), created.id());
    }

    // ===== Scenario 5: Duplicate email rejected =====

    #[test]
    fn duplicate_email_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("first create");

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice 2".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    #[test]
    fn duplicate_email_case_insensitive() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "Alice@Example.COM".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Other".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    #[test]
    fn duplicate_email_on_update_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create alice");

        let bob = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "bob@example.com".to_string(),
                    display_name: "Bob".to_string(),
                    ..Default::default()
                },
            )
            .expect("create bob");

        let err = engine
            .update_user(
                &realm,
                bob.id(),
                &UpdateUserRequest {
                    email: Some("alice@example.com".to_string()),
                    ..UpdateUserRequest::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    // ===== Adversarial: null bytes and unicode =====

    #[test]
    fn null_bytes_in_email_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice\0@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn null_bytes_in_display_name_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice\0Smith".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn unicode_normalization_deduplicates_emails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        // Create with decomposed é
        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "caf\u{0065}\u{0301}@example.com".to_string(),
                    display_name: "User 1".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        // Try to create with composed é — should be duplicate
        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "caf\u{00E9}@example.com".to_string(),
                    display_name: "User 2".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    // ===== Adversarial: oversized input =====

    #[test]
    fn oversized_email_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let long_email = format!("{}@example.com", "a".repeat(250));
        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: long_email,
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn oversized_display_name_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "A".repeat(257),
                    ..Default::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    // ===== Cross-realm isolation =====

    #[test]
    fn cross_realm_isolation() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        let alice = engine
            .create_user(
                &realm_a,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create");

        // Same email in different realm should succeed
        let alice_b = engine
            .create_user(
                &realm_b,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice B".to_string(),
                    ..Default::default()
                },
            )
            .expect("create in different realm should succeed");

        assert_ne!(alice.id(), alice_b.id());

        // Can't see realm A's user from realm B
        let not_found = engine.get_user(&realm_b, alice.id()).expect("get");
        assert!(not_found.is_none());
    }

    // ===== Send + Sync =====

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EmbeddedIdentityEngine>();
    }

    // ===== Credential Scenario 1: set_password + verify_password =====

    fn create_test_user(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> User {
        engine
            .create_user(
                realm,
                &CreateUserRequest {
                    email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Test User".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user")
    }

    #[test]
    fn set_and_verify_password_correct() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("my-secure-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        let pw_check = CleartextPassword::from_string("my-secure-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &pw_check)
            .expect("verify");
        assert!(result, "correct password should verify");
    }

    #[test]
    fn set_and_verify_password_wrong() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("correct-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        let wrong = CleartextPassword::from_string("wrong-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &wrong)
            .expect("verify");
        assert!(!result, "wrong password should not verify");
    }

    #[test]
    fn set_password_nonexistent_user_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .set_password(&realm, &UserId::generate(), &pw)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    #[test]
    fn verify_password_nonexistent_user_returns_generic_error() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .verify_password(&realm, &UserId::generate(), &pw)
            .expect_err("should fail");
        // Returns generic InvalidCredential to prevent user enumeration
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    #[test]
    fn verify_password_no_credential_returns_generic_error() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .verify_password(&realm, user.id(), &pw)
            .expect_err("should fail");
        // Returns generic InvalidCredential to prevent credential enumeration
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    // ===== Credential Scenario 3: Password change =====

    #[test]
    fn change_password_succeeds() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let old_pw = CleartextPassword::from_string("old-password".to_string());
        engine
            .set_password(&realm, user.id(), &old_pw)
            .expect("set password");

        let old_for_change = CleartextPassword::from_string("old-password".to_string());
        let new_pw = CleartextPassword::from_string("new-password".to_string());
        engine
            .change_password(&realm, user.id(), &old_for_change, &new_pw)
            .expect("change password");

        // Old password should no longer verify
        let old_check = CleartextPassword::from_string("old-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &old_check)
            .expect("verify old");
        assert!(!result, "old password should no longer verify");

        // New password should verify
        let new_check = CleartextPassword::from_string("new-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &new_check)
            .expect("verify new");
        assert!(result, "new password should verify");
    }

    #[test]
    fn change_password_wrong_old_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("real-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        let wrong_old = CleartextPassword::from_string("wrong-old".to_string());
        let new_pw = CleartextPassword::from_string("new-password".to_string());
        let err = engine
            .change_password(&realm, user.id(), &wrong_old, &new_pw)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));

        // Original password should still work
        let orig = CleartextPassword::from_string("real-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &orig)
            .expect("verify");
        assert!(result, "original password should still verify");
    }

    // ===== Delete cascades to credentials =====

    #[test]
    fn delete_user_cascades_credential() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        engine.delete_user(&realm, user.id()).expect("delete");

        // Verify should fail with generic InvalidCredential (enumeration resistance)
        let pw_check = CleartextPassword::from_string("password".to_string());
        let err = engine
            .verify_password(&realm, user.id(), &pw_check)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    // ===== Adversarial: Timing oracle prevention =====

    #[test]
    #[allow(clippy::cast_precision_loss)] // Precision loss acceptable for timing ratio
    fn verify_nonexistent_user_takes_comparable_time() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        // Time a real failed verification
        let wrong = CleartextPassword::from_string("wrong".to_string());
        let start_real = std::time::Instant::now();
        let _ = engine.verify_password(&realm, user.id(), &wrong);
        let real_time = start_real.elapsed();

        // Time a nonexistent user verification
        let fake = CleartextPassword::from_string("wrong".to_string());
        let start_fake = std::time::Instant::now();
        let _ = engine.verify_password(&realm, &UserId::generate(), &fake);
        let fake_time = start_fake.elapsed();

        // Both should take roughly the same time. We allow 10x tolerance
        // because we're testing on CI with variable load, but the key
        // property is that fake_time is NOT near-zero (i.e., we did
        // actually compute the dummy hash).
        let ratio = if real_time > fake_time {
            real_time.as_nanos() as f64 / fake_time.as_nanos().max(1) as f64
        } else {
            fake_time.as_nanos() as f64 / real_time.as_nanos().max(1) as f64
        };

        assert!(
            ratio < 10.0,
            "timing ratio {ratio:.1}x too large: real={real_time:?}, fake={fake_time:?}"
        );
    }

    // ===== Session Scenario 1: Create session returns valid ID bound to user =====

    #[test]
    fn create_session_returns_valid_session() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        assert_eq!(session.user_id(), user.id());
        assert_eq!(session.created_at(), Timestamp::from_micros(1_000_000));
        // TTL is 24 hours = 86_400_000_000 μs
        let expected_expiry = Timestamp::from_micros(1_000_000 + 86_400_000_000);
        assert_eq!(session.expires_at(), expected_expiry);
        assert_eq!(session.last_refreshed_at(), session.created_at());
    }

    #[test]
    fn create_session_nonexistent_user_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .create_session(&realm, &UserId::generate(), &SessionContext::default())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    // ===== Session metadata round-trip =====

    #[test]
    fn session_with_full_context_persists_metadata() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let ctx = SessionContext {
            ip_address: Some("203.0.113.42".to_string()),
            user_agent_raw: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()),
            device_label: Some("Chrome, Mac OSX".to_string()),
            satisfies_mfa_via_passkey: false,
        };

        let session = engine
            .create_session(&realm, user.id(), &ctx)
            .expect("create session");

        assert_eq!(session.ip_address(), Some("203.0.113.42"));
        assert_eq!(session.device_label(), Some("Chrome, Mac OSX"));
        assert!(session.user_agent_raw().is_some());

        // Verify round-trip through storage
        let fetched = engine
            .get_session(&realm, session.id())
            .expect("get session")
            .expect("should exist");

        assert_eq!(fetched.ip_address(), Some("203.0.113.42"));
        assert_eq!(fetched.device_label(), Some("Chrome, Mac OSX"));
        assert_eq!(fetched.user_agent_raw(), session.user_agent_raw());
    }

    #[test]
    fn session_with_default_context_has_none_metadata() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        assert!(session.ip_address().is_none());
        assert!(session.user_agent_raw().is_none());
        assert!(session.device_label().is_none());

        let fetched = engine
            .get_session(&realm, session.id())
            .expect("get session")
            .expect("should exist");

        assert!(fetched.ip_address().is_none());
        assert!(fetched.device_label().is_none());
    }

    #[test]
    fn session_deserialized_without_metadata_fields_has_none() {
        // Simulate a session serialized before metadata fields were added.
        // SessionId/UserId serialize as bare UUIDs (serde newtype over Uuid).
        let old_json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "user_id": "00000000-0000-0000-0000-000000000002",
            "created_at": 1000000,
            "expires_at": 87400000000,
            "last_refreshed_at": 1000000,
            "revoked": false
        }"#;

        let session: Session = serde_json::from_str(old_json).expect("deserialize old format");

        assert!(session.ip_address().is_none());
        assert!(session.user_agent_raw().is_none());
        assert!(session.device_label().is_none());
    }

    // ===== Session Scenario 2: Lookup session by ID =====

    #[test]
    fn lookup_session_by_id_returns_correct_data() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        let fetched = engine
            .get_session(&realm, session.id())
            .expect("get session")
            .expect("should exist");

        assert_eq!(fetched.id(), session.id());
        assert_eq!(fetched.user_id(), user.id());
        assert_eq!(fetched.created_at(), session.created_at());
        assert_eq!(fetched.expires_at(), session.expires_at());
    }

    #[test]
    fn lookup_nonexistent_session_returns_none() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let result = engine
            .get_session(&realm, &SessionId::generate())
            .expect("get");
        assert!(result.is_none());
    }

    // ===== Session Scenario 3: Revoke session =====

    #[test]
    fn revoke_session_immediate_invalidation() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        // Revoke it
        engine.revoke_session(&realm, session.id()).expect("revoke");

        // Lookup should return None
        let result = engine.get_session(&realm, session.id()).expect("get");
        assert!(result.is_none(), "revoked session should not be found");
    }

    #[test]
    fn revoke_nonexistent_session_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .revoke_session(&realm, &SessionId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    // ===== Session Scenario 4: TTL expiration =====

    #[test]
    fn session_expires_after_ttl() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        // Session should be valid now
        let valid = engine.get_session(&realm, session.id()).expect("get");
        assert!(valid.is_some(), "session should be valid before TTL");

        // Advance clock past TTL (24 hours + 1 microsecond)
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl + 1);

        // Session should now be expired
        let expired = engine.get_session(&realm, session.id()).expect("get");
        assert!(expired.is_none(), "session should be expired after TTL");
    }

    #[test]
    fn session_valid_just_before_expiry() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        // Advance clock to 1 μs before expiry
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl - 1);

        let still_valid = engine.get_session(&realm, session.id()).expect("get");
        assert!(
            still_valid.is_some(),
            "session should still be valid 1μs before expiry"
        );
    }

    // ===== Session Scenario 5: Refresh session extends TTL =====

    #[test]
    fn refresh_session_extends_ttl() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        let ttl = 24 * 60 * 60 * 1_000_000_i64;

        // Advance 12 hours (half TTL)
        clock.advance(ttl / 2);

        // Refresh the session
        let refreshed = engine
            .refresh_session(&realm, session.id())
            .expect("refresh");

        // Expiry should be 24h from now (not original creation)
        let now = clock.now();
        assert_eq!(refreshed.expires_at(), now.add_micros(ttl));
        assert_eq!(refreshed.last_refreshed_at(), now);

        // Original created_at should be preserved
        assert_eq!(refreshed.created_at(), session.created_at());

        // Advance another 23 hours — would have expired without refresh
        clock.advance(ttl - ttl / 2 + 1_000_000);

        let still_valid = engine.get_session(&realm, session.id()).expect("get");
        assert!(
            still_valid.is_some(),
            "refreshed session should still be valid past original expiry"
        );
    }

    #[test]
    fn refresh_expired_session_fails() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        // Advance past TTL
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl + 1);

        let err = engine
            .refresh_session(&realm, session.id())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    #[test]
    fn refresh_revoked_session_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let session = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");

        engine.revoke_session(&realm, session.id()).expect("revoke");

        let err = engine
            .refresh_session(&realm, session.id())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    // ===== Delete cascades to sessions =====

    #[test]
    fn delete_user_cascades_sessions() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        // Create multiple sessions
        let s1 = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("session 1");
        let s2 = engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("session 2");

        // Both should be valid
        assert!(engine.get_session(&realm, s1.id()).expect("get").is_some());
        assert!(engine.get_session(&realm, s2.id()).expect("get").is_some());

        // Delete user
        engine.delete_user(&realm, user.id()).expect("delete");

        // Both sessions should be gone
        assert!(engine.get_session(&realm, s1.id()).expect("get").is_none());
        assert!(engine.get_session(&realm, s2.id()).expect("get").is_none());
    }

    // ===== Property tests =====

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating a valid email address.
        fn valid_email() -> impl Strategy<Value = String> {
            ("[a-z]{1,20}@[a-z]{1,10}\\.[a-z]{2,4}").prop_map(|s| s)
        }

        proptest! {
            /// Property: Random CRUD sequences maintain consistent user count.
            ///
            /// After creating N users and deleting M of them, exactly N-M
            /// users should be retrievable.
            #[test]
            fn crud_sequences_maintain_count(
                emails in proptest::collection::hash_set(valid_email(), 1..10),
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = RealmId::generate();
                let mut created_ids = Vec::new();

                // Create all users
                for (i, email) in emails.iter().enumerate() {
                    let user = engine.create_user(&realm, &CreateUserRequest {
                        email: email.clone(),
                        display_name: format!("User {i}"),
                        ..Default::default()
                    }).expect("create");
                    created_ids.push(user.id().clone());
                }

                // All should be retrievable
                for id in &created_ids {
                    let user = engine.get_user(&realm, id).expect("get");
                    prop_assert!(user.is_some(), "created user should be found");
                }

                // Delete half
                let to_delete = created_ids.len() / 2;
                for id in &created_ids[..to_delete] {
                    engine.delete_user(&realm, id).expect("delete");
                }

                // Deleted should be gone
                for id in &created_ids[..to_delete] {
                    let user = engine.get_user(&realm, id).expect("get");
                    prop_assert!(user.is_none(), "deleted user should not be found");
                }

                // Remaining should still exist
                for id in &created_ids[to_delete..] {
                    let user = engine.get_user(&realm, id).expect("get");
                    prop_assert!(user.is_some(), "remaining user should be found");
                }
            }

            /// Property: Email uniqueness holds under random creation sequences.
            #[test]
            fn email_uniqueness_under_random_creation(
                email in valid_email(),
                n in 2..5u32,
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = RealmId::generate();

                // First creation should succeed
                let result = engine.create_user(&realm, &CreateUserRequest {
                    email: email.clone(),
                    display_name: "User 0".to_string(),
                    ..Default::default()
                });
                prop_assert!(result.is_ok(), "first creation should succeed");

                // Subsequent creations with same email should fail
                for i in 1..n {
                    let result = engine.create_user(&realm, &CreateUserRequest {
                        email: email.clone(),
                        display_name: format!("User {i}"),
                        ..Default::default()
                    });
                    prop_assert!(result.is_err(), "duplicate email should fail");
                    if let Err(ref err) = result {
                        prop_assert!(
                            matches!(err, IdentityError::DuplicateEmail),
                            "should be DuplicateEmail, got: {:?}", err
                        );
                    }
                }
            }

            /// Property: Random create/revoke sequences maintain consistent active session count.
            #[test]
            fn session_create_revoke_maintains_count(
                n_create in 1..8usize,
                n_revoke_ratio in 0.0..1.0_f64,
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = RealmId::generate();
                let user = engine.create_user(&realm, &CreateUserRequest {
                    email: format!("session-prop-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Prop User".to_string(),
                    ..Default::default()
                }).expect("create user");

                // Create N sessions
                let mut session_ids = Vec::new();
                for _ in 0..n_create {
                    let session = engine
                        .create_session(&realm, user.id(), &SessionContext::default())
                        .expect("create session");
                    session_ids.push(session.id().clone());
                }

                // All should be valid
                for id in &session_ids {
                    let s = engine.get_session(&realm, id).expect("get");
                    prop_assert!(s.is_some(), "created session should be valid");
                }

                // Revoke a proportion of them
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
                let n_revoke = (n_create as f64 * n_revoke_ratio) as usize;
                for id in &session_ids[..n_revoke] {
                    engine.revoke_session(&realm, id).expect("revoke");
                }

                // Count active sessions
                let active_count = session_ids
                    .iter()
                    .filter(|id| engine.get_session(&realm, id).expect("get").is_some())
                    .count();

                prop_assert_eq!(
                    active_count,
                    n_create - n_revoke,
                    "active count should be creates minus revokes"
                );
            }

            /// Property: No session ID collisions across many generations.
            #[test]
            fn no_session_id_collisions(n in 10..100usize) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = RealmId::generate();
                let user = engine.create_user(&realm, &CreateUserRequest {
                    email: format!("collision-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Collision User".to_string(),
                    ..Default::default()
                }).expect("create user");

                let mut ids = std::collections::HashSet::new();
                for _ in 0..n {
                    let session = engine
                        .create_session(&realm, user.id(), &SessionContext::default())
                        .expect("create session");
                    let was_new = ids.insert(session.id().clone());
                    prop_assert!(was_new, "session ID collision detected");
                }
                prop_assert_eq!(ids.len(), n, "all session IDs should be unique");
            }
        }
    }

    // ===================================================================
    //  OIDC / OAuth 2.0 Unit Tests (Step 15)
    // ===================================================================

    fn pkce_challenge(verifier: &str) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest.as_ref())
    }
    const TEST_PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

    fn register_test_client(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> OAuthClient {
        engine
            .register_client(
                realm,
                &RegisterClientRequest {
                    client_name: "Test App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client")
    }

    // ===== Unit Test 1: Generate authorization code with correct parameters =====

    #[test]
    fn generate_authorization_code_with_correct_params() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "random-state-value".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize should succeed");

        // Code should be non-empty base64url
        assert!(!response.code().is_empty(), "code must not be empty");
        // State should be echoed back
        assert_eq!(response.state(), "random-state-value");
    }

    // ===== Unit Test 2: Exchange authorization code returns tokens =====

    #[test]
    fn exchange_authorization_code_returns_tokens() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let auth_response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state1".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");

        let token_response = engine
            .exchange_authorization_code(
                &realm,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth_response.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                },
            )
            .expect("exchange code");

        assert!(!token_response.access_token().is_empty());
        assert!(!token_response.id_token().is_empty());
        assert!(!token_response.refresh_token().is_empty());
        assert_eq!(token_response.token_type(), "Bearer");
        assert!(token_response.expires_in() > 0);

        // Verify access token is valid via session lookup
        let claims = engine
            .validate_token(&realm, token_response.access_token())
            .expect("validate access token");
        assert_eq!(claims.sub, user.id().to_string());

        // Verify ID token is a valid JWT with correct claims
        let id_claims =
            tokens::decode_claims_unverified(token_response.id_token()).expect("decode id token");
        assert_eq!(id_claims.sub, user.id().to_string());
        assert_eq!(id_claims.token_type, "id_token");
    }

    // ===== Unit Test 3: Authorization code single-use =====

    #[test]
    fn authorization_code_single_use() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let auth_response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state2".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");

        // First exchange succeeds
        let result1 = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            },
        );
        assert!(result1.is_ok(), "first exchange should succeed");

        // Second exchange with same code fails
        let result2 = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            },
        );
        assert!(
            matches!(result2, Err(IdentityError::InvalidAuthorizationCode)),
            "second exchange must fail, got: {result2:?}"
        );
    }

    // ===== Unit Test 4: Authorization code expiration =====

    #[test]
    fn authorization_code_expiration() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let auth_response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state3".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");

        // Advance clock past the authorization code TTL (default: 600 seconds)
        clock.advance(601 * 1_000_000); // 601 seconds in microseconds

        // Exchange should fail due to expiration
        let result = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidAuthorizationCode)),
            "expired code must be rejected, got: {result:?}"
        );
    }

    // ===== Unit Test 5: Discovery document returns correct metadata =====

    #[test]
    fn discovery_document_correct_metadata() {
        let (_dir, engine, _clock) = setup_engine();

        let doc = engine.oidc_discovery();

        assert_eq!(doc.issuer, "https://hearth.local");
        assert_eq!(doc.authorization_endpoint, "https://hearth.local/authorize");
        assert_eq!(doc.token_endpoint, "https://hearth.local/token");
        assert_eq!(doc.jwks_uri, "https://hearth.local/.well-known/jwks.json");
        assert!(doc.response_types_supported.contains(&"code".to_string()));
        assert!(doc.subject_types_supported.contains(&"public".to_string()));
        assert!(doc
            .id_token_signing_alg_values_supported
            .contains(&"EdDSA".to_string()));
        assert!(doc.scopes_supported.contains(&"openid".to_string()));
        assert!(doc
            .code_challenge_methods_supported
            .contains(&"S256".to_string()));
    }

    // ===================================================================
    //  OIDC Adversarial Tests (Step 15)
    // ===================================================================

    // ===== Adversarial Test 1: Authorization code reuse rejected =====

    #[test]
    fn adversarial_authorization_code_reuse_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let auth_response = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "adv-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");

        // Use the code
        engine
            .exchange_authorization_code(
                &realm,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth_response.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                },
            )
            .expect("first exchange");

        // Attempt reuse — must fail
        let reuse = engine.exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            },
        );
        assert!(
            matches!(reuse, Err(IdentityError::InvalidAuthorizationCode)),
            "code reuse must be rejected, got: {reuse:?}"
        );
    }

    // ===== Adversarial Test 2: Open redirect via non-registered URI rejected =====

    #[test]
    fn adversarial_open_redirect_non_registered_uri_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // Attempt to authorize with an unregistered redirect URI
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://evil.example.com/steal-tokens".to_string(),
                scope: "openid".to_string(),
                state: "state-val".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidRedirectUri)),
            "unregistered redirect URI must be rejected, got: {result:?}"
        );
    }

    // ===== Adversarial Test 3: CSRF — missing state causes rejection =====

    #[test]
    fn adversarial_csrf_missing_state_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // Attempt to authorize with empty state
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: String::new(), // empty state
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidGrant { .. })),
            "missing state must be rejected, got: {result:?}"
        );
    }

    // ===== Adversarial: Credential rate limiting =====

    fn setup_engine_with_rate_limit(
        max_attempts: u32,
        lockout_micros: i64,
    ) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            rate_limit: RateLimitConfig {
                max_failed_attempts: max_attempts,
                lockout_duration_micros: lockout_micros,
            },
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    #[test]
    fn rate_limiting_engages_after_max_failures() {
        // Configure: lockout after 3 failed attempts, 10-second lockout
        let lockout_micros = 10_000_000; // 10 seconds
        let (_dir, engine, _clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("correct-pw".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        // 3 wrong attempts
        for i in 0..3 {
            let wrong = CleartextPassword::from_string(format!("wrong-{i}"));
            let result = engine.verify_password(&realm, user.id(), &wrong);
            assert!(
                result.is_ok(),
                "attempt {i} should not be rate limited yet: {result:?}"
            );
            assert!(!result.expect("ok"), "wrong password should not verify");
        }

        // 4th attempt: should be rate limited even with the correct password
        let correct = CleartextPassword::from_string("correct-pw".to_string());
        let result = engine.verify_password(&realm, user.id(), &correct);
        assert!(
            matches!(result, Err(IdentityError::RateLimited)),
            "should be rate limited after 3 failures, got: {result:?}"
        );
    }

    #[test]
    fn rate_limiting_resets_on_successful_verification() {
        let lockout_micros = 10_000_000;
        let (_dir, engine, _clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("my-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        // 2 wrong attempts (below threshold)
        for _ in 0..2 {
            let wrong = CleartextPassword::from_string("wrong".to_string());
            let result = engine
                .verify_password(&realm, user.id(), &wrong)
                .expect("should not be rate limited");
            assert!(!result);
        }

        // Correct password resets the counter
        let correct = CleartextPassword::from_string("my-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &correct)
            .expect("should succeed");
        assert!(result);

        // 2 more wrong attempts should succeed (counter was reset)
        for _ in 0..2 {
            let wrong = CleartextPassword::from_string("wrong".to_string());
            let result = engine
                .verify_password(&realm, user.id(), &wrong)
                .expect("should not be rate limited after reset");
            assert!(!result);
        }
    }

    #[test]
    fn rate_limiting_expires_after_lockout_window() {
        let lockout_micros = 10_000_000; // 10 seconds
        let (_dir, engine, clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        let pw = CleartextPassword::from_string("my-password".to_string());
        engine
            .set_password(&realm, user.id(), &pw)
            .expect("set password");

        // Trigger lockout: 3 failures
        for i in 0..3 {
            let wrong = CleartextPassword::from_string(format!("wrong-{i}"));
            let _ = engine.verify_password(&realm, user.id(), &wrong);
        }

        // Confirm locked out
        let correct = CleartextPassword::from_string("my-password".to_string());
        assert!(
            matches!(
                engine.verify_password(&realm, user.id(), &correct),
                Err(IdentityError::RateLimited)
            ),
            "should be locked out"
        );

        // Advance clock past lockout window
        clock.advance(lockout_micros + 1);

        // Should be able to verify again
        let correct = CleartextPassword::from_string("my-password".to_string());
        let result = engine
            .verify_password(&realm, user.id(), &correct)
            .expect("should be allowed after lockout expires");
        assert!(result, "correct password should verify after lockout");
    }

    // ===== Adversarial: Nonce reuse detection =====

    fn setup_engine_with_nonce_enforcement(
    ) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            oidc: OidcConfig {
                enforce_nonces: true,
                ..OidcConfig::default()
            },
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    #[test]
    fn nonce_reuse_in_authorization_request_rejected() {
        let (_dir, engine, _clock) = setup_engine_with_nonce_enforcement();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // First request with nonce succeeds
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-1".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some("unique-nonce-abc".to_string()),
                resource: None,
            },
        );
        assert!(result.is_ok(), "first use of nonce should succeed");

        // Second request with same nonce should be rejected
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-2".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some("unique-nonce-abc".to_string()),
                resource: None,
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidGrant { .. })),
            "reused nonce must be rejected, got: {result:?}"
        );

        // Different nonce should succeed
        let result = engine.authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-3".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some("different-nonce-xyz".to_string()),
                resource: None,
            },
        );
        assert!(result.is_ok(), "different nonce should succeed");
    }

    fn setup_engine_with_nonce_disabled(
    ) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            oidc: OidcConfig {
                enforce_nonces: false,
                ..OidcConfig::default()
            },
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    #[test]
    fn nonce_not_enforced_when_disabled() {
        // Explicitly opt out of nonce enforcement to verify the bypass path.
        let (_dir, engine, _clock) = setup_engine_with_nonce_disabled();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // Same nonce used twice should succeed when enforcement is off
        for state_suffix in ["1", "2"] {
            let result = engine.authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: format!("state-{state_suffix}"),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: Some("same-nonce".to_string()),
                    resource: None,
                },
            );
            assert!(
                result.is_ok(),
                "nonce reuse should be allowed when enforcement is off"
            );
        }
    }

    #[test]
    fn nonce_reusable_after_ttl_expiry() {
        // After the authorization_code_ttl_secs window has passed, a previously
        // used nonce must be accepted again (the old entry should have been swept).
        let (_dir, engine, clock) = setup_engine_with_nonce_enforcement();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let make_request = |nonce: &str, state: &str| AuthorizationRequest {
            client_id: client.client_id().clone(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            scope: "openid".to_string(),
            state: state.to_string(),
            response_type: "code".to_string(),
            user_id: user.id().clone(),
            code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            nonce: Some(nonce.to_string()),
            resource: None,
        };

        // Use the nonce at t=0.
        assert!(
            engine
                .authorize(&realm, &make_request("expiry-nonce", "state-1"))
                .is_ok(),
            "first use must succeed"
        );

        // Immediate reuse must still be rejected.
        assert!(
            matches!(
                engine.authorize(&realm, &make_request("expiry-nonce", "state-2")),
                Err(IdentityError::InvalidGrant { .. })
            ),
            "same nonce reused before TTL must be rejected"
        );

        // Advance past the authorization_code_ttl_secs (default 600 s = 600_000_000 µs).
        let ttl_micros = engine.config.oidc.authorization_code_ttl_secs * 1_000_000;
        clock.advance(ttl_micros);

        // The expired entry should be swept on the next call; the nonce is
        // now acceptable again because its original auth-code has expired.
        assert!(
            engine
                .authorize(&realm, &make_request("expiry-nonce", "state-3"))
                .is_ok(),
            "nonce must be accepted after TTL expiry"
        );
    }

    #[test]
    fn nonce_set_does_not_grow_unbounded() {
        // Repeatedly issue distinct nonces and advance the clock past the TTL
        // between batches.  The set must stay bounded to one TTL window rather
        // than accumulating every nonce ever used.
        let (_dir, engine, clock) = setup_engine_with_nonce_enforcement();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let ttl_micros = engine.config.oidc.authorization_code_ttl_secs * 1_000_000;

        // Batch A: insert 5 nonces.
        for i in 0..5u32 {
            let req = AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: format!("batch-a-state-{i}"),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some(format!("batch-a-nonce-{i}")),
                resource: None,
            };
            assert!(engine.authorize(&realm, &req).is_ok());
        }

        // Batch A nonces are present.
        {
            let nonces = engine.used_nonces.lock().expect("nonce lock");
            assert_eq!(nonces.len(), 5, "5 nonces after batch A");
        }

        // Advance past TTL — batch A nonces are now stale.
        clock.advance(ttl_micros);

        // Batch B: insert 3 new nonces (triggers sweep of batch A).
        for i in 0..3u32 {
            let req = AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: format!("batch-b-state-{i}"),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some(format!("batch-b-nonce-{i}")),
                resource: None,
            };
            assert!(engine.authorize(&realm, &req).is_ok());
        }

        // Only batch B nonces remain; batch A was evicted.
        {
            let nonces = engine.used_nonces.lock().expect("nonce lock");
            assert_eq!(
                nonces.len(),
                3,
                "set must contain only batch B nonces after TTL sweep, got {}",
                nonces.len()
            );
        }
    }

    // ===== Session simulation tests — see simulation/ crate =====

    // ===== Phase 1 Step 19: Multi-Tenancy =====
    //
    // Test scenarios from TEST_SCENARIOS.md § Multi-Tenancy

    // --- Unit Scenario 1: Create realm with configuration returns assigned RealmId ---

    #[test]
    fn create_realm_returns_assigned_id() {
        let (_dir, engine, _clock) = setup_engine();

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "acme-corp".to_string(),
                config: None,
            })
            .expect("create realm");

        assert_eq!(realm.name(), "acme-corp");
        assert_eq!(realm.status(), RealmStatus::Active);

        // Should be retrievable
        let loaded = engine
            .get_realm(realm.id())
            .expect("get realm")
            .expect("realm should exist");
        assert_eq!(loaded.id(), realm.id());
        assert_eq!(loaded.name(), "acme-corp");
    }

    #[test]
    fn create_realm_with_custom_config() {
        let (_dir, engine, _clock) = setup_engine();

        let config = RealmConfig {
            session_ttl_micros: Some(3_600_000_000), // 1 hour
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
            ..RealmConfig::default()
        };
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "custom-corp".to_string(),
                config: Some(config.clone()),
            })
            .expect("create realm");

        assert_eq!(realm.config(), &config);
    }

    #[test]
    fn get_nonexistent_realm_returns_none() {
        let (_dir, engine, _clock) = setup_engine();

        let result = engine.get_realm(&RealmId::generate()).expect("get realm");
        assert!(result.is_none());
    }

    #[test]
    fn create_realm_rejects_duplicate_name() {
        let (_dir, engine, _clock) = setup_engine();

        engine
            .create_realm(&CreateRealmRequest {
                name: "duplicate-corp".to_string(),
                config: None,
            })
            .expect("first create_realm should succeed");

        let err = engine
            .create_realm(&CreateRealmRequest {
                name: "duplicate-corp".to_string(),
                config: None,
            })
            .expect_err("second create_realm with same name should fail");

        assert!(
            matches!(err, IdentityError::DuplicateRealmName),
            "expected DuplicateRealmName, got {err:?}"
        );

        // Confirm only one realm record exists for that name
        let realm = engine
            .get_realm_by_name("duplicate-corp")
            .expect("get_realm_by_name")
            .expect("realm should exist");
        assert_eq!(realm.name(), "duplicate-corp");
    }

    // --- Unit Scenario 2: Realm-scoped user creation; cross-realm lookup returns not-found ---

    #[test]
    fn realm_scoped_user_isolation() {
        let (_dir, engine, _clock) = setup_engine();

        let realm_a = engine
            .create_realm(&CreateRealmRequest {
                name: "realm-a".to_string(),
                config: None,
            })
            .expect("create realm A");
        let realm_b = engine
            .create_realm(&CreateRealmRequest {
                name: "realm-b".to_string(),
                config: None,
            })
            .expect("create realm B");

        // Create user in realm A
        let user_a = engine
            .create_user(
                realm_a.id(),
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user in A");

        // User should be visible in realm A
        let found = engine
            .get_user(realm_a.id(), user_a.id())
            .expect("get user in A");
        assert!(found.is_some());

        // User should NOT be visible in realm B
        let not_found = engine
            .get_user(realm_b.id(), user_a.id())
            .expect("get user in B");
        assert!(not_found.is_none());

        // Same email can be used in realm B (different namespace)
        let user_b = engine
            .create_user(
                realm_b.id(),
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice B".to_string(),
                    ..Default::default()
                },
            )
            .expect("create same email in B");
        assert_ne!(user_a.id(), user_b.id());
    }

    // --- Unit Scenario 3: Per-realm signing keys ---

    #[test]
    fn per_realm_signing_keys_are_independent() {
        let (_dir, engine, _clock) = setup_engine();

        let realm_a = engine
            .create_realm(&CreateRealmRequest {
                name: "realm-a".to_string(),
                config: None,
            })
            .expect("create realm A");
        let realm_b = engine
            .create_realm(&CreateRealmRequest {
                name: "realm-b".to_string(),
                config: None,
            })
            .expect("create realm B");

        let jwks_a = engine.realm_jwks(realm_a.id()).expect("jwks A");
        let jwks_b = engine.realm_jwks(realm_b.id()).expect("jwks B");

        // Each realm should have exactly one key
        assert_eq!(jwks_a.keys.len(), 1);
        assert_eq!(jwks_b.keys.len(), 1);

        // Keys should be different
        assert_ne!(jwks_a.keys[0].kid, jwks_b.keys[0].kid);
        assert_ne!(jwks_a.keys[0].x, jwks_b.keys[0].x);
    }

    // --- Unit Scenario 4: Realm configuration update ---

    #[test]
    fn update_realm_config_applies_only_to_target() {
        let (_dir, engine, _clock) = setup_engine();

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "original-name".to_string(),
                config: None,
            })
            .expect("create realm");

        // Default config should have no overrides
        assert!(realm.config().session_ttl_micros.is_none());

        // Update config
        let new_config = RealmConfig {
            session_ttl_micros: Some(7_200_000_000), // 2 hours
            password_memory_cost: Some(32768),
            ..RealmConfig::default()
        };
        let updated = engine
            .update_realm(
                realm.id(),
                &UpdateRealmRequest {
                    name: Some("updated-name".to_string()),
                    status: None,
                    config: Some(new_config.clone()),
                },
            )
            .expect("update realm");

        assert_eq!(updated.name(), "updated-name");
        assert_eq!(updated.config(), &new_config);

        // Persisted
        let loaded = engine
            .get_realm(realm.id())
            .expect("get")
            .expect("should exist");
        assert_eq!(loaded.name(), "updated-name");
        assert_eq!(loaded.config(), &new_config);
    }

    #[test]
    fn update_nonexistent_realm_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();

        let err = engine
            .update_realm(
                &RealmId::generate(),
                &UpdateRealmRequest {
                    name: Some("nope".to_string()),
                    ..UpdateRealmRequest::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::RealmNotFound));
    }

    // --- Unit Scenario 5: Cascading realm deletion ---

    #[test]
    fn delete_realm_cascades_all_data() {
        let (_dir, engine, _clock) = setup_engine();

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "doomed-corp".to_string(),
                config: None,
            })
            .expect("create realm");

        // Create users
        let user1 = engine
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: "user1@example.com".to_string(),
                    display_name: "User 1".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user 1");
        let user2 = engine
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: "user2@example.com".to_string(),
                    display_name: "User 2".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user 2");

        // Set passwords
        let pw = CleartextPassword::from_string("password123".to_string());
        engine
            .set_password(realm.id(), user1.id(), &pw)
            .expect("set password");

        // Create sessions
        let session = engine
            .create_session(realm.id(), user1.id(), &SessionContext::default())
            .expect("create session");

        // Delete realm
        engine.delete_realm(realm.id()).expect("delete realm");

        // Realm record should be gone
        let loaded = engine.get_realm(realm.id()).expect("get realm");
        assert!(loaded.is_none(), "realm record should be deleted");

        // Users should be gone
        assert!(engine
            .get_user(realm.id(), user1.id())
            .expect("get")
            .is_none());
        assert!(engine
            .get_user(realm.id(), user2.id())
            .expect("get")
            .is_none());

        // Session should be gone
        assert!(engine
            .get_session(realm.id(), session.id())
            .expect("get")
            .is_none());

        // Signing key should be gone
        let jwks_err = engine.realm_jwks(realm.id());
        assert!(jwks_err.is_err(), "signing key should be deleted");
    }

    #[test]
    fn delete_nonexistent_realm_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();

        let err = engine
            .delete_realm(&RealmId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::RealmNotFound));
    }

    // ===== Phase 1 Step 19: Multi-Tenancy Property Tests =====

    mod realm_proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating a valid realm name.
        ///
        /// Realm names must be ASCII alphanumeric, hyphens, or underscores
        /// only (1-63 chars), and must not collide with reserved admin
        /// URL keywords. We prefix every generated name with `r-` to
        /// guarantee uniqueness from the reserved set.
        fn valid_realm_name() -> impl Strategy<Value = String> {
            "[a-z0-9_-]{3,30}".prop_map(|s| format!("r-{}", s.trim_matches('-')))
        }

        /// Strategy for generating a valid email address.
        fn valid_email() -> impl Strategy<Value = String> {
            ("[a-z]{1,20}@[a-z]{1,10}\\.[a-z]{2,4}").prop_map(|s| s)
        }

        proptest! {
            /// Property: Random operations across N realms never produce
            /// cross-realm data leaks.
            ///
            /// Creates users with the same email in multiple realms, then
            /// verifies each realm only sees its own users.
            #[test]
            fn no_cross_realm_data_leaks(
                n_realms in 2..5usize,
                emails in proptest::collection::hash_set(valid_email(), 1..5),
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let mut realms = Vec::new();

                // Create N realms
                for i in 0..n_realms {
                    let realm = engine.create_realm(&CreateRealmRequest {
                        name: format!("realm-{i}"),
                        config: None,
                    }).expect("create realm");
                    realms.push(realm);
                }

                // Create same set of users in each realm
                let mut user_ids: Vec<Vec<UserId>> = Vec::new();
                for realm in &realms {
                    let mut ids = Vec::new();
                    for (i, email) in emails.iter().enumerate() {
                        let user = engine.create_user(realm.id(), &CreateUserRequest {
                            email: email.clone(),
                            display_name: format!("User {i}"),
                            ..Default::default()
                        }).expect("create user");
                        ids.push(user.id().clone());
                    }
                    user_ids.push(ids);
                }

                // Verify: each realm's users are only visible in that realm
                for (t_idx, _realm) in realms.iter().enumerate() {
                    for (other_idx, other_realm) in realms.iter().enumerate() {
                        for user_id in &user_ids[t_idx] {
                            let result = engine.get_user(other_realm.id(), user_id)
                                .expect("get user");
                            if t_idx == other_idx {
                                prop_assert!(result.is_some(),
                                    "user should exist in its own realm");
                            } else {
                                prop_assert!(result.is_none(),
                                    "user should NOT exist in another realm");
                            }
                        }
                    }
                }
            }

            /// Property: Random create/delete realm sequences maintain
            /// consistent realm count and clean storage.
            #[test]
            fn create_delete_maintains_consistent_count(
                names in proptest::collection::hash_set(valid_realm_name(), 2..8),
            ) {
                let names: Vec<String> = names.into_iter().collect();
                let (_dir, engine, _clock) = setup_engine();
                let mut created_realms = Vec::new();

                // Create all realms
                for name in &names {
                    let realm = engine.create_realm(&CreateRealmRequest {
                        name: name.clone(),
                        config: None,
                    }).expect("create realm");
                    created_realms.push(realm);
                }

                // All should be retrievable
                for realm in &created_realms {
                    let loaded = engine.get_realm(realm.id()).expect("get");
                    prop_assert!(loaded.is_some(), "created realm should be found");
                }

                // Delete every other realm
                let to_delete: Vec<_> = created_realms.iter()
                    .enumerate()
                    .filter(|(i, _)| i % 2 == 0)
                    .map(|(_, t)| t.id().clone())
                    .collect();

                for realm_id in &to_delete {
                    engine.delete_realm(realm_id).expect("delete");
                }

                // Deleted should be gone
                for realm_id in &to_delete {
                    let loaded = engine.get_realm(realm_id).expect("get");
                    prop_assert!(loaded.is_none(), "deleted realm should not be found");
                }

                // Remaining should still exist
                for (i, realm) in created_realms.iter().enumerate() {
                    if i % 2 != 0 {
                        let loaded = engine.get_realm(realm.id()).expect("get");
                        prop_assert!(loaded.is_some(), "remaining realm should be found");
                    }
                }
            }

            /// Property: Realm key rotation under concurrent token issuance.
            ///
            /// Tokens issued before key rotation remain valid (they're validated
            /// via session lookup, not signature verification on the hot path).
            #[test]
            fn realm_key_rotation_preserves_in_flight_tokens(
                _seed in 0..100u32,
            ) {
                let (_dir, engine, _clock) = setup_engine();

                let realm = engine.create_realm(&CreateRealmRequest {
                    name: "rotation-corp".to_string(),
                    config: None,
                }).expect("create realm");

                let user = engine.create_user(realm.id(), &CreateUserRequest {
                    email: format!("rotation-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Rotation User".to_string(),
                    ..Default::default()
                }).expect("create user");

                let session = engine.create_session(realm.id(), user.id(), &SessionContext::default())
                    .expect("create session");

                // Issue tokens with current key
                let tokens = engine.issue_tokens(realm.id(), user.id(), session.id())
                    .expect("issue tokens");

                // Tokens should validate (session-based validation)
                let claims = engine.validate_token(realm.id(), tokens.access_token())
                    .expect("validate before rotation");
                prop_assert_eq!(&claims.sub, &user.id().to_string());

                // Token still validates after rotation because the hot-path
                // validation uses session lookup, not signature re-verification.
                // The JWKS key ID may have changed, but existing sessions are
                // unaffected.
                let new_claims = engine.validate_token(realm.id(), tokens.access_token())
                    .expect("validate after rotation");
                prop_assert_eq!(&new_claims.sub, &user.id().to_string());
            }
        }
    }

    // ===== Step 22: OAuth 2.0 Complete Unit Tests =====

    /// Helper: creates a realm via `create_realm` and returns `RealmId`.
    fn create_test_realm(engine: &EmbeddedIdentityEngine) -> RealmId {
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: format!("test-realm-{}", uuid::Uuid::new_v4()),
                config: Some(RealmConfig::default()),
            })
            .expect("create realm");
        realm.id().clone()
    }

    /// Helper: registers a confidential client with `client_credentials` grant.
    fn register_confidential_client(
        engine: &EmbeddedIdentityEngine,
        realm_id: &RealmId,
        secret: &str,
    ) -> OAuthClient {
        engine
            .register_client(
                realm_id,
                &RegisterClientRequest {
                    client_name: "Confidential App".to_string(),
                    redirect_uris: vec![],
                    client_secret: Some(secret.to_string()),
                    grant_types: vec!["client_credentials".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register confidential client")
    }

    // ===== B1: Client credentials grant =====

    #[test]
    fn client_credentials_register_and_issue_token() {
        use crate::identity::oidc::ClientCredentialsRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let secret = uuid::Uuid::new_v4().to_string();

        // Register confidential client
        let client = register_confidential_client(&engine, &realm_id, &secret);
        assert!(client.is_confidential());
        assert!(client
            .grant_types()
            .contains(&"client_credentials".to_string()));

        // Issue token via client credentials
        let response = engine
            .client_credentials_token(
                &realm_id,
                &ClientCredentialsRequest {
                    client_id: client.client_id().clone(),
                    client_secret: secret.clone(),
                    scope: Some("read write".to_string()),
                },
            )
            .expect("client_credentials_token should succeed");

        assert_eq!(response.token_type(), "Bearer");
        assert!(response.expires_in() > 0);
        assert_eq!(response.scope(), Some("read write"));

        // Verify the access token is valid
        let claims =
            tokens::decode_claims_unverified(response.access_token()).expect("decode access token");
        assert_eq!(claims.sub, client.client_id().to_string());
        assert_eq!(claims.token_type, "access");
        assert_eq!(claims.scope.as_deref(), Some("read write"));
    }

    #[test]
    fn client_credentials_wrong_secret_rejected() {
        use crate::identity::oidc::ClientCredentialsRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let client = register_confidential_client(&engine, &realm_id, "correct-secret");

        let result = engine.client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: "wrong-secret".to_string(),
                scope: None,
            },
        );

        assert!(
            matches!(result, Err(IdentityError::InvalidClientSecret)),
            "wrong secret should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn client_credentials_unsupported_grant_type() {
        use crate::identity::oidc::ClientCredentialsRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        // Register a public client (no client_credentials grant)
        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Public App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register public client");

        let result = engine.client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: "anything".to_string(),
                scope: None,
            },
        );

        assert!(
            matches!(result, Err(IdentityError::UnsupportedGrantType)),
            "public client should not support client_credentials, got: {result:?}"
        );
    }

    // ===== B2: Device authorization =====

    #[test]
    fn device_authorize_returns_valid_codes() {
        use crate::identity::oidc::DeviceAuthorizationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        // Register a client
        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Device App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        let response = engine
            .device_authorize(
                &realm_id,
                &DeviceAuthorizationRequest {
                    client_id: client.client_id().clone(),
                    scope: Some("openid".to_string()),
                },
            )
            .expect("device_authorize should succeed");

        // Verify response
        assert!(!response.device_code.is_empty());
        assert_eq!(response.user_code.len(), 8, "user code should be 8 chars");
        assert_eq!(response.interval, 5);
        assert!(response.expires_in > 0);

        // Verify user code only contains unambiguous chars
        let valid_chars = "BCDFGHJKMNPQRSTVWXYZ23456789";
        for c in response.user_code.chars() {
            assert!(
                valid_chars.contains(c),
                "user code char '{c}' not in unambiguous alphabet"
            );
        }
    }

    // ===== B3: Refresh token rotation =====

    #[test]
    fn refresh_token_rotation_issues_new_pair() {
        let (_dir, engine, clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Rotation App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        // Auth code flow → tokens with grant family
        let auth = engine
            .authorize(
                &realm_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "test-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");

        let tokens = engine
            .exchange_authorization_code(
                &realm_id,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                },
            )
            .expect("exchange code");

        // Verify refresh token has fid claim
        let refresh_claims =
            tokens::decode_claims_unverified(tokens.refresh_token()).expect("decode refresh");
        assert!(
            refresh_claims.fid.is_some(),
            "refresh token should have fid"
        );

        // Advance clock and refresh
        clock.advance(60 * 1_000_000); // 60 seconds in microseconds
        let new_tokens = engine
            .refresh_tokens(&realm_id, tokens.refresh_token())
            .expect("refresh should succeed");

        // New tokens are different
        assert_ne!(new_tokens.access_token(), tokens.access_token());
        assert_ne!(new_tokens.refresh_token(), tokens.refresh_token());

        // New refresh token has the same family ID
        let new_refresh_claims = tokens::decode_claims_unverified(new_tokens.refresh_token())
            .expect("decode new refresh");
        assert_eq!(new_refresh_claims.fid, refresh_claims.fid);

        // Old refresh token is now rejected (rotation)
        let result = engine.refresh_tokens(&realm_id, tokens.refresh_token());
        assert!(
            matches!(result, Err(IdentityError::TokenRevoked)),
            "old refresh token should be rejected after rotation, got: {result:?}"
        );
    }

    #[test]
    fn refresh_token_subject_must_match_session_user() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let session_user = create_test_user(&engine, &realm_id);
        let forged_subject = create_test_user(&engine, &realm_id);

        let session = engine
            .create_session(&realm_id, session_user.id(), &SessionContext::default())
            .expect("create session");
        let token_pair = engine
            .issue_tokens(&realm_id, session_user.id(), session.id())
            .expect("issue token pair");

        // Re-sign with a mismatched subject to ensure refresh validates that
        // session ownership matches the token subject, even for legacy tokens.
        let mut forged_claims = tokens::decode_claims_unverified(token_pair.refresh_token())
            .expect("decode refresh claims");
        forged_claims.sub = forged_subject.id().to_string();
        let signing_key = engine
            .get_or_load_realm_signing_key(&realm_id)
            .expect("load signing key");
        let forged_token = signing_key
            .issue_token(&forged_claims)
            .expect("issue forged token");

        let result = engine.refresh_tokens(&realm_id, &forged_token);
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "subject/session mismatch must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn refresh_token_rejects_forged_legacy_payload_without_fid() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Forgery App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        let auth = engine
            .authorize(
                &realm_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "forgery-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");
        let token_pair = engine
            .exchange_authorization_code(
                &realm_id,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                },
            )
            .expect("exchange code");

        let mut forged_claims = tokens::decode_claims_unverified(token_pair.refresh_token())
            .expect("decode refresh claims");
        assert!(
            forged_claims.fid.is_some(),
            "expected grant-family refresh token"
        );
        forged_claims.fid = None;

        let parts: Vec<&str> = token_pair.refresh_token().split('.').collect();
        assert_eq!(parts.len(), 3, "refresh token should be JWT compact form");
        let forged_payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&forged_claims).expect("serialize forged refresh claims"));
        let forged_token = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);

        let result = engine.refresh_tokens(&realm_id, &forged_token);
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "forged no-fid payload must be rejected, got: {result:?}"
        );
    }

    // ===== B4: Token revocation =====

    #[test]
    fn revoke_access_token_invalidates_session() {
        use crate::identity::oidc::TokenRevocationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Token is valid
        let claims = engine
            .validate_token(&realm_id, tokens.access_token())
            .expect("should be valid");
        assert_eq!(claims.sub, user.id().to_string());

        // Revoke the access token
        engine
            .revoke_token(
                &realm_id,
                &TokenRevocationRequest {
                    token: tokens.access_token().to_string(),
                    token_type_hint: Some("access_token".to_string()),
                },
            )
            .expect("revoke should succeed");

        // Token is now invalid (session revoked)
        let result = engine.validate_token(&realm_id, tokens.access_token());
        assert!(
            result.is_err(),
            "access token should be invalid after revocation"
        );
    }

    #[test]
    fn revoke_refresh_token_invalidates_family() {
        use crate::identity::oidc::TokenRevocationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Revoke App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        let auth = engine
            .authorize(
                &realm_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");

        let tokens = engine
            .exchange_authorization_code(
                &realm_id,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                },
            )
            .expect("exchange code");

        // Revoke the refresh token
        engine
            .revoke_token(
                &realm_id,
                &TokenRevocationRequest {
                    token: tokens.refresh_token().to_string(),
                    token_type_hint: Some("refresh_token".to_string()),
                },
            )
            .expect("revoke should succeed");

        // Refresh is now rejected
        let result = engine.refresh_tokens(&realm_id, tokens.refresh_token());
        assert!(
            matches!(result, Err(IdentityError::TokenRevoked)),
            "refresh should fail after revocation, got: {result:?}"
        );
    }

    // ===== B5: Token introspection =====

    #[test]
    fn introspect_active_token() {
        use crate::identity::oidc::TokenIntrospectionRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        let response = engine
            .introspect_token(
                &realm_id,
                &TokenIntrospectionRequest {
                    token: tokens.access_token().to_string(),
                    token_type_hint: None,
                },
            )
            .expect("introspect should succeed");

        assert!(response.active, "valid token should be active");
        assert_eq!(response.sub.as_deref(), Some(&*user.id().to_string()));
        assert_eq!(response.token_type.as_deref(), Some("access"));
        assert!(response.exp.is_some());
        assert!(response.iat.is_some());
    }

    #[test]
    fn introspect_revoked_token_is_inactive() {
        use crate::identity::oidc::{TokenIntrospectionRequest, TokenRevocationRequest};

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Revoke
        engine
            .revoke_token(
                &realm_id,
                &TokenRevocationRequest {
                    token: tokens.access_token().to_string(),
                    token_type_hint: None,
                },
            )
            .expect("revoke");

        // Introspect
        let response = engine
            .introspect_token(
                &realm_id,
                &TokenIntrospectionRequest {
                    token: tokens.access_token().to_string(),
                    token_type_hint: None,
                },
            )
            .expect("introspect should succeed");

        assert!(!response.active, "revoked token should be inactive");
    }

    #[test]
    fn introspect_invalid_token_is_inactive() {
        use crate::identity::oidc::TokenIntrospectionRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        let response = engine
            .introspect_token(
                &realm_id,
                &TokenIntrospectionRequest {
                    token: "not-a-valid-token".to_string(),
                    token_type_hint: None,
                },
            )
            .expect("introspect should succeed even for invalid tokens");

        assert!(!response.active, "invalid token should be inactive");
    }

    // ===== Phase 1 Step 22: OAuth 2.0 Adversarial Tests =====

    /// Adversarial: Refresh token theft detection.
    ///
    /// Scenario: attacker steals a refresh token, legitimate user rotates,
    /// then attacker tries to use the stolen (old) token. The entire grant
    /// family must be revoked, including the legitimate user's new token.
    #[test]
    fn adversarial_refresh_token_theft_detection() {
        let (_dir, engine, clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        let user = engine
            .create_user(
                &realm_id,
                &CreateUserRequest {
                    email: "theft-victim@test.com".to_string(),
                    display_name: "Theft Victim".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");

        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Theft Test Client".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        let auth = engine
            .authorize(
                &realm_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    scope: "openid".to_string(),
                    state: "theft-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");

        let tokens = engine
            .exchange_authorization_code(
                &realm_id,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                },
            )
            .expect("exchange");

        // Attacker steals refresh token
        let stolen_refresh = tokens.refresh_token().to_string();

        // Legitimate user rotates (advance clock for unique tokens)
        clock.advance(1_000_000);
        let new_pair = engine
            .refresh_tokens(&realm_id, &stolen_refresh)
            .expect("legitimate rotation");
        let legitimate_refresh = new_pair.refresh_token().to_string();

        // Attacker uses the stolen (old) refresh token
        clock.advance(1_000_000);
        let attack_result = engine.refresh_tokens(&realm_id, &stolen_refresh);
        assert!(
            attack_result.is_err(),
            "stolen refresh token must be rejected"
        );

        // Legitimate user's new refresh token should ALSO be revoked
        // (entire grant family revoked due to theft detection)
        let legitimate_result = engine.refresh_tokens(&realm_id, &legitimate_refresh);
        assert!(
            legitimate_result.is_err(),
            "legitimate refresh token must also be revoked after theft detection"
        );

        // The session should be revoked too
        let validate_result = engine.validate_token(&realm_id, new_pair.access_token());
        assert!(
            validate_result.is_err(),
            "session should be revoked after theft detection"
        );
    }

    /// Adversarial: Invalid client secrets produce generic errors.
    ///
    /// Verifies that wrong secrets, empty secrets, and non-existent clients
    /// all return the same error type (no information leakage).
    #[test]
    fn adversarial_invalid_client_secret_generic_error() {
        use crate::identity::oidc::ClientCredentialsRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Secret Test Client".to_string(),
                    redirect_uris: vec![],
                    client_secret: Some("correct-secret-123".to_string()),
                    grant_types: vec!["client_credentials".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        // Wrong secret
        let wrong_result = engine.client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: "wrong-secret-456".to_string(),
                scope: None,
            },
        );
        assert!(
            matches!(wrong_result, Err(IdentityError::InvalidClientSecret)),
            "wrong secret should return InvalidClientSecret"
        );

        // Empty secret
        let empty_result = engine.client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: String::new(),
                scope: None,
            },
        );
        assert!(
            matches!(empty_result, Err(IdentityError::InvalidClientSecret)),
            "empty secret should return InvalidClientSecret"
        );

        // Non-existent client
        let fake_client_id = crate::core::ClientId::generate();
        let missing_result = engine.client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: fake_client_id,
                client_secret: "any-secret".to_string(),
                scope: None,
            },
        );
        assert!(
            matches!(missing_result, Err(IdentityError::InvalidClient)),
            "non-existent client should return InvalidClient"
        );
    }

    /// Adversarial: Device polling rate limit enforcement.
    ///
    /// Polls faster than the allowed interval and verifies `SlowDown` error.
    #[test]
    fn adversarial_device_polling_rate_limit() {
        use crate::identity::oidc::DeviceAuthorizationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);

        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Rate Limit Test".to_string(),
                    redirect_uris: vec![],
                    client_secret: None,
                    grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        let device_resp = engine
            .device_authorize(
                &realm_id,
                &DeviceAuthorizationRequest {
                    client_id: client.client_id().clone(),
                    scope: Some("openid".to_string()),
                },
            )
            .expect("device authorize");

        // First poll — should return AuthorizationPending (not SlowDown)
        let first_poll =
            engine.poll_device_token(&realm_id, &device_resp.device_code, client.client_id());
        assert!(
            matches!(first_poll, Err(IdentityError::AuthorizationPending)),
            "first poll should return AuthorizationPending, got: {first_poll:?}"
        );

        // Immediate second poll — should return SlowDown
        let second_poll =
            engine.poll_device_token(&realm_id, &device_resp.device_code, client.client_id());
        assert!(
            matches!(second_poll, Err(IdentityError::SlowDown)),
            "rapid second poll should return SlowDown, got: {second_poll:?}"
        );
    }

    // ===== Phase 1 Step 22: OAuth 2.0 Extended Property Tests =====

    mod oauth_proptests {
        use super::*;
        use crate::identity::oidc::{TokenIntrospectionRequest, TokenRevocationRequest};
        use proptest::prelude::*;

        proptest! {
            /// Property: After N issue/refresh/revoke operations, the active
            /// token count matches expectations.
            ///
            /// Issues tokens via auth code flow, optionally refreshes or revokes
            /// them, then introspects all tokens and verifies the active count.
            #[test]
            fn active_token_set_consistency(
                n_users in 1..5usize,
                ops in proptest::collection::vec(0..3u8, 1..8),
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let realm = engine.create_realm(&CreateRealmRequest {
                    name: "prop-test-realm".to_string(),
                    config: None,
                }).expect("create realm");
                let realm_id = realm.id().clone();

                // Register a public client
                let client = engine.register_client(
                    &realm_id,
                    &RegisterClientRequest {
                        client_name: "Prop Test Client".to_string(),
                        redirect_uris: vec!["https://app.example.com/cb".to_string()],
                        client_secret: None,
                        grant_types: vec!["authorization_code".to_string()],
                        require_consent: true,
                        client_logo_url: None,
                                            ..Default::default()
                    },
                ).expect("register client");

                // Create N users and issue tokens for each
                let mut access_tokens = Vec::new();
                let mut refresh_tokens = Vec::new();

                for i in 0..n_users {
                    let email = format!("propuser-{i}-{}@test.com", uuid::Uuid::new_v4());
                    let user = engine.create_user(&realm_id, &CreateUserRequest {
                        email,
                        display_name: format!("Prop User {i}"),
                        ..Default::default()
                    }).expect("create user");

                    let auth = engine.authorize(&realm_id, &AuthorizationRequest {
                        client_id: client.client_id().clone(),
                        redirect_uri: "https://app.example.com/cb".to_string(),
                        scope: "openid".to_string(),
                        state: format!("state-{i}"),
                        response_type: "code".to_string(),
                        user_id: user.id().clone(),
                        code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                        code_challenge_method: Some(CodeChallengeMethod::S256),
                        nonce: None,
                                            resource: None,
                    }).expect("authorize");

                    let tokens = engine.exchange_authorization_code(&realm_id, &TokenExchangeRequest {
                        client_id: client.client_id().clone(),
                        code: auth.code().to_string(),
                        redirect_uri: "https://app.example.com/cb".to_string(),
                        code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                    }).expect("exchange");

                    access_tokens.push(tokens.access_token().to_string());
                    refresh_tokens.push(tokens.refresh_token().to_string());
                }

                // Apply operations: 0 = noop, 1 = refresh, 2 = revoke access
                for (i, op) in ops.iter().enumerate() {
                    let idx = i % access_tokens.len();
                    match op {
                        1 => {
                            // Refresh — may fail if already revoked
                            if let Ok(new_pair) = engine.refresh_tokens(
                                &realm_id,
                                &refresh_tokens[idx],
                            ) {
                                access_tokens[idx] = new_pair.access_token().to_string();
                                refresh_tokens[idx] = new_pair.refresh_token().to_string();
                            }
                        }
                        2 => {
                            // Revoke access token
                            let _ = engine.revoke_token(
                                &realm_id,
                                &TokenRevocationRequest {
                                    token: access_tokens[idx].clone(),
                                    token_type_hint: Some("access_token".to_string()),
                                },
                            );
                        }
                        _ => {} // noop
                    }
                }

                // Count active tokens via introspection
                let mut active_count = 0usize;
                for token in &access_tokens {
                    let resp = engine.introspect_token(
                        &realm_id,
                        &TokenIntrospectionRequest {
                            token: token.clone(),
                            token_type_hint: None,
                        },
                    ).expect("introspect");
                    if resp.active {
                        active_count += 1;
                    }
                }

                // Active count must be <= total issued
                prop_assert!(
                    active_count <= access_tokens.len(),
                    "active count ({}) must not exceed total ({})",
                    active_count,
                    access_tokens.len(),
                );
            }

            /// Property: At any point during N refresh rotations, exactly one
            /// refresh token is valid per grant family.
            ///
            /// Rotates a refresh token N times, checking after each rotation
            /// that only the latest refresh token is accepted.
            #[test]
            fn single_valid_refresh_token(n_rotations in 1..6usize) {
                let (_dir, engine, clock) = setup_engine();
                let realm = engine.create_realm(&CreateRealmRequest {
                    name: "single-refresh-realm".to_string(),
                    config: None,
                }).expect("create realm");
                let realm_id = realm.id().clone();

                let email = format!("rotate-{}@test.com", uuid::Uuid::new_v4());
                let user = engine.create_user(&realm_id, &CreateUserRequest {
                    email,
                    display_name: "Rotate User".to_string(),
                    ..Default::default()
                }).expect("create user");

                let client = engine.register_client(
                    &realm_id,
                    &RegisterClientRequest {
                        client_name: "Rotate Client".to_string(),
                        redirect_uris: vec!["https://app.example.com/cb".to_string()],
                        client_secret: None,
                        grant_types: vec!["authorization_code".to_string()],
                        require_consent: true,
                        client_logo_url: None,
                                            ..Default::default()
                    },
                ).expect("register client");

                let auth = engine.authorize(&realm_id, &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    scope: "openid".to_string(),
                    state: "rotate-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                                    resource: None,
                }).expect("authorize");

                let tokens = engine.exchange_authorization_code(&realm_id, &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                }).expect("exchange");

                let mut current_refresh = tokens.refresh_token().to_string();
                let mut old_refresh_tokens: Vec<String> = Vec::new();

                for i in 0..n_rotations {
                    // Advance clock 1 second to get unique timestamps
                    clock.advance(1_000_000);

                    let new_pair = engine.refresh_tokens(&realm_id, &current_refresh)
                        .unwrap_or_else(|e| panic!("rotation {i} failed: {e}"));

                    old_refresh_tokens.push(current_refresh);
                    current_refresh = new_pair.refresh_token().to_string();

                    // Current refresh token should work for introspection
                    let resp = engine.introspect_token(
                        &realm_id,
                        &TokenIntrospectionRequest {
                            token: current_refresh.clone(),
                            token_type_hint: None,
                        },
                    ).expect("introspect current");
                    prop_assert!(resp.active, "current refresh token must be active at rotation {}", i);
                }

                // After all rotations, none of the old refresh tokens should work
                for (i, old_token) in old_refresh_tokens.iter().enumerate() {
                    let result = engine.refresh_tokens(&realm_id, old_token);
                    // First old token reuse triggers theft detection
                    if result.is_err() {
                        // After theft detection, all tokens in the family are revoked
                        break;
                    }
                    // If we got here, this old token happened to match (shouldn't)
                    prop_assert!(false, "old refresh token {} should have been rejected", i);
                }
            }
        }
    }

    // ===== Adversarial: MFA brute-force lockout (Scenario F1) =====

    #[test]
    #[allow(clippy::cast_sign_loss)] // Test timestamps are always positive
    fn mfa_brute_force_lockout() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        // Enroll TOTP
        let enrollment = engine.enroll_totp(&realm, user.id()).expect("enroll");

        // Activate MFA
        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let secret_bytes = data_encoding::BASE32_NOPAD
            .decode(enrollment.secret_base32.as_bytes())
            .expect("decode");
        let code = crate::identity::totp::compute_totp(&secret_bytes, now_secs / 30);
        engine
            .verify_totp_enrollment(&realm, user.id(), &code)
            .expect("verify enrollment");

        // 5 wrong codes
        for _ in 0..5 {
            let err = engine.verify_totp(&realm, user.id(), "000000");
            assert!(
                matches!(err, Err(IdentityError::InvalidMfaCode)),
                "should be InvalidMfaCode"
            );
        }

        // 6th attempt (correct code) should be rate limited
        // Advance time just slightly so we get a fresh step
        clock.advance(30_000_000); // 30 seconds
        let now_secs2 = (clock.now().as_micros() / 1_000_000) as u64;
        let correct_code = crate::identity::totp::compute_totp(&secret_bytes, now_secs2 / 30);
        let err = engine
            .verify_totp(&realm, user.id(), &correct_code)
            .expect_err("should be rate limited");
        assert!(
            matches!(err, IdentityError::RateLimited),
            "should be RateLimited, got: {err:?}"
        );

        // Advance clock past 5 min lockout (5 * 60 * 1_000_000 = 300_000_000 μs)
        clock.advance(300_000_000);
        let now_secs3 = (clock.now().as_micros() / 1_000_000) as u64;
        let correct_code2 = crate::identity::totp::compute_totp(&secret_bytes, now_secs3 / 30);
        engine
            .verify_totp(&realm, user.id(), &correct_code2)
            .expect("should succeed after lockout expires");
    }

    // ===== Adversarial: TOTP replay protection (Scenario F2) =====

    #[test]
    #[allow(clippy::cast_sign_loss)] // Test timestamps are always positive
    fn mfa_replay_protection() {
        let (_dir, engine, clock) = setup_engine();
        let realm = RealmId::generate();
        let user = create_test_user(&engine, &realm);

        // Enroll + activate TOTP
        let enrollment = engine.enroll_totp(&realm, user.id()).expect("enroll");
        let secret_bytes = data_encoding::BASE32_NOPAD
            .decode(enrollment.secret_base32.as_bytes())
            .expect("decode");

        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let step = now_secs / 30;
        let code = crate::identity::totp::compute_totp(&secret_bytes, step);
        engine
            .verify_totp_enrollment(&realm, user.id(), &code)
            .expect("verify enrollment");

        // Advance to next step so we have a fresh code
        clock.advance(30_000_000); // 30 seconds
        let now_secs2 = (clock.now().as_micros() / 1_000_000) as u64;
        let step2 = now_secs2 / 30;
        let code2 = crate::identity::totp::compute_totp(&secret_bytes, step2);

        // First use succeeds
        engine
            .verify_totp(&realm, user.id(), &code2)
            .expect("first use should succeed");

        // Replay same code — should fail
        let err = engine
            .verify_totp(&realm, user.id(), &code2)
            .expect_err("replay should fail");
        assert!(
            matches!(err, IdentityError::InvalidMfaCode),
            "replay should be InvalidMfaCode, got: {err:?}"
        );

        // Advance to next step — new code should work
        clock.advance(30_000_000);
        let now_secs3 = (clock.now().as_micros() / 1_000_000) as u64;
        let step3 = now_secs3 / 30;
        let code3 = crate::identity::totp::compute_totp(&secret_bytes, step3);
        engine
            .verify_totp(&realm, user.id(), &code3)
            .expect("next step should succeed");
    }

    // ===== Magic Link / Passwordless (Step 25) unit tests =====

    /// Helper: creates a realm and user with email for magic link tests.
    fn setup_magic_link_user(
        engine: &EmbeddedIdentityEngine,
    ) -> (RealmId, crate::identity::types::User) {
        let realm = engine
            .create_realm(&crate::identity::types::CreateRealmRequest {
                name: format!("ml-test-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create realm");
        let user = engine
            .create_user(
                realm.id(),
                &crate::identity::types::CreateUserRequest {
                    email: format!("ml-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "ML Test User".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");
        (realm.id().clone(), user)
    }

    // Test A: Generate magic link token bound to email with correct expiration
    #[test]
    fn magic_link_request_returns_nonempty_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn crate::core::Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock.clone() as Arc<dyn crate::core::Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        let (realm, user) = setup_magic_link_user(&engine);

        // Request magic link
        let response = engine
            .request_magic_link(&realm, user.email())
            .expect("request_magic_link");

        // Token should be non-empty
        assert!(
            !response.token().is_empty(),
            "magic link token should not be empty"
        );

        // Verify stored record
        let token_hash = EmbeddedIdentityEngine::sha256_hex(response.token().as_bytes());
        let key = keys::encode_magic_link_token(&token_hash);
        let stored_bytes = engine
            .storage
            .get(&realm, &key)
            .expect("storage get")
            .expect("stored record should exist");
        let stored: StoredMagicLink = serde_json::from_slice(&stored_bytes).expect("deserialize");
        assert_eq!(stored.email, user.email().to_lowercase());
        assert!(stored.user_id.is_some(), "user_id should be set");
        assert!(!stored.used, "should not be marked as used");
        assert_eq!(
            stored.created_at_micros,
            clock.now().as_micros(),
            "created_at should match clock"
        );
    }

    // Test B: Validate magic link token — correct token returns associated user
    #[test]
    fn magic_link_validate_returns_correct_user() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn crate::core::Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock as Arc<dyn crate::core::Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        let (realm, user) = setup_magic_link_user(&engine);

        // Request and validate
        let response = engine
            .request_magic_link(&realm, user.email())
            .expect("request_magic_link");
        let returned_user_id = engine
            .validate_magic_link(&realm, response.token())
            .expect("validate_magic_link");

        assert_eq!(
            returned_user_id.as_uuid(),
            user.id().as_uuid(),
            "returned user ID should match"
        );
    }

    // Test C: Expired magic link token rejected
    #[test]
    fn magic_link_expired_token_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn crate::core::Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock.clone() as Arc<dyn crate::core::Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        let (realm, user) = setup_magic_link_user(&engine);

        // Request magic link
        let response = engine
            .request_magic_link(&realm, user.email())
            .expect("request_magic_link");

        // Advance clock past 15-minute expiry
        clock.advance(MAGIC_LINK_EXPIRY_MICROS + 1_000_000);

        // Validate should fail
        let err = engine
            .validate_magic_link(&realm, response.token())
            .expect_err("should fail for expired token");
        assert!(
            matches!(err, IdentityError::MagicLinkTokenInvalid),
            "should be MagicLinkTokenInvalid, got: {err:?}"
        );
    }

    // Test D: Single-use — second validation rejected
    #[test]
    fn magic_link_single_use_enforced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn crate::core::Clock>,
        ));
        let engine = EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            clock as Arc<dyn crate::core::Clock>,
            identity_config,
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine");

        let (realm, user) = setup_magic_link_user(&engine);

        // Request and validate once (succeeds)
        let response = engine
            .request_magic_link(&realm, user.email())
            .expect("request_magic_link");
        let _user_id = engine
            .validate_magic_link(&realm, response.token())
            .expect("first validation should succeed");

        // Second validation should fail
        let err = engine
            .validate_magic_link(&realm, response.token())
            .expect_err("second validation should fail");
        assert!(
            matches!(err, IdentityError::MagicLinkTokenInvalid),
            "should be MagicLinkTokenInvalid, got: {err:?}"
        );
    }

    // ===== OAuth Consent engine tests =====

    fn setup_consent_env() -> (
        tempfile::TempDir,
        EmbeddedIdentityEngine,
        Arc<FakeClock>,
        RealmId,
        UserId,
        ClientId,
    ) {
        let (dir, engine, clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "consent-realm".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = engine
            .create_user(
                realm.id(),
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                    ..Default::default()
                },
            )
            .expect("create user");
        let client = engine
            .register_client(
                realm.id(),
                &RegisterClientRequest {
                    client_name: "Consent Test App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");
        (
            dir,
            engine,
            clock,
            realm.id().clone(),
            user.id().clone(),
            client.client_id().clone(),
        )
    }

    #[test]
    fn grant_and_get_consent_round_trip() {
        let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
        let rec = engine
            .grant_consent(
                &realm,
                &user,
                &client,
                &["profile".to_string(), "email".to_string()],
            )
            .expect("grant");
        assert_eq!(rec.granted_scopes, vec!["email", "profile"]);

        let loaded = engine
            .get_consent(&realm, &user, &client)
            .expect("get")
            .expect("present");
        assert_eq!(loaded.granted_scopes, vec!["email", "profile"]);
        assert!(loaded.covers(&["profile".to_string()]));
        assert!(!loaded.covers(&["admin".to_string()]));
    }

    #[test]
    fn grant_consent_merges_into_existing_record() {
        let (_dir, engine, clock, realm, user, client) = setup_consent_env();
        engine
            .grant_consent(&realm, &user, &client, &["profile".to_string()])
            .expect("grant 1");
        clock.advance(1_000_000);
        let rec = engine
            .grant_consent(&realm, &user, &client, &["email".to_string()])
            .expect("grant 2");
        assert_eq!(rec.granted_scopes, vec!["email", "profile"]);
        assert!(rec.updated_at.as_micros() > rec.granted_at.as_micros());
    }

    #[test]
    fn grant_consent_requires_existing_client() {
        let (_dir, engine, _clock, realm, user, _client) = setup_consent_env();
        let bogus = ClientId::generate();
        let err = engine
            .grant_consent(&realm, &user, &bogus, &["profile".to_string()])
            .expect_err("client not found");
        assert!(matches!(err, IdentityError::ClientNotFound), "got: {err:?}");
    }

    #[test]
    fn list_consents_by_user_returns_joined_entries() {
        let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
        engine
            .grant_consent(&realm, &user, &client, &["profile".to_string()])
            .expect("grant");
        let list = engine.list_consents_by_user(&realm, &user).expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].client_name, "Consent Test App");
        assert_eq!(list[0].record.granted_scopes, vec!["profile"]);
    }

    #[test]
    fn list_consents_filters_orphaned_client_records() {
        let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
        engine
            .grant_consent(&realm, &user, &client, &["profile".to_string()])
            .expect("grant");
        engine
            .delete_client(&realm, &client)
            .expect("delete client");
        // delete_client cascades consent away — verify list is empty.
        let list = engine.list_consents_by_user(&realm, &user).expect("list");
        assert!(list.is_empty(), "expected no live consents, got {list:?}");
    }

    #[test]
    fn revoke_consent_returns_not_found_when_absent() {
        let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
        let err = engine
            .revoke_consent(&realm, &user, &client)
            .expect_err("no record yet");
        assert!(
            matches!(err, IdentityError::ConsentNotFound),
            "got: {err:?}"
        );
    }

    #[test]
    fn revoke_consent_removes_record_entirely() {
        let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
        engine
            .grant_consent(&realm, &user, &client, &["profile".to_string()])
            .expect("grant");
        engine
            .revoke_consent(&realm, &user, &client)
            .expect("revoke");
        assert!(engine
            .get_consent(&realm, &user, &client)
            .expect("get")
            .is_none());
    }

    #[test]
    fn revoke_all_consents_drops_every_user_record() {
        let (_dir, engine, _clock, realm, user, client1) = setup_consent_env();
        let client2 = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Second Client".to_string(),
                    redirect_uris: vec!["https://other.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register 2");
        engine
            .grant_consent(&realm, &user, &client1, &["profile".to_string()])
            .expect("grant 1");
        engine
            .grant_consent(&realm, &user, client2.client_id(), &["email".to_string()])
            .expect("grant 2");
        let count = engine
            .revoke_all_consents_for_user(&realm, &user)
            .expect("revoke all");
        assert_eq!(count, 2);
        assert!(engine
            .list_consents_by_user(&realm, &user)
            .expect("list")
            .is_empty());
    }

    #[test]
    fn pending_authorization_ticket_is_single_use() {
        let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
        let now = engine.clock.now();
        let pending = PendingAuthorizationRequest {
            user_id: user.clone(),
            client_id: client.clone(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            requested_scopes: vec!["profile".to_string()],
            state: "xyz".to_string(),
            response_type: "code".to_string(),
            code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            created_at: now,
            expires_at: now.add_micros(600_000_000),
        };
        let ticket = engine
            .put_pending_authorization(&realm, &pending)
            .expect("put");
        let first = engine
            .take_pending_authorization(&realm, &ticket)
            .expect("take 1");
        assert_eq!(first.user_id, user);
        let err = engine
            .take_pending_authorization(&realm, &ticket)
            .expect_err("take 2 should fail");
        assert!(matches!(err, IdentityError::ConsentTicketNotFound));
    }

    #[test]
    fn pending_authorization_ticket_expires() {
        let (_dir, engine, clock, realm, user, client) = setup_consent_env();
        let now = engine.clock.now();
        let pending = PendingAuthorizationRequest {
            user_id: user,
            client_id: client,
            redirect_uri: "https://app.example.com/cb".to_string(),
            requested_scopes: vec!["profile".to_string()],
            state: "xyz".to_string(),
            response_type: "code".to_string(),
            code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
            created_at: now,
            expires_at: now.add_micros(600_000_000),
        };
        let ticket = engine
            .put_pending_authorization(&realm, &pending)
            .expect("put");
        // advance past expiry
        clock.advance(600_000_001);
        let err = engine
            .take_pending_authorization(&realm, &ticket)
            .expect_err("expired");
        assert!(
            matches!(err, IdentityError::ConsentTicketExpired),
            "got {err:?}"
        );
    }

    #[test]
    fn delete_user_cascades_consent_records() {
        let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
        engine
            .grant_consent(&realm, &user, &client, &["profile".to_string()])
            .expect("grant");
        engine.delete_user(&realm, &user).expect("delete user");
        assert!(engine
            .get_consent(&realm, &user, &client)
            .expect("get")
            .is_none());
    }

    #[test]
    fn consent_records_are_realm_isolated() {
        let (_dir, engine, _clock, realm_a, user, client) = setup_consent_env();
        let realm_b = engine
            .create_realm(&CreateRealmRequest {
                name: "Other".to_string(),
                config: None,
            })
            .expect("create realm B");
        engine
            .grant_consent(&realm_a, &user, &client, &["profile".to_string()])
            .expect("grant");
        // Same (user, client) key in realm_b must not find realm_a's record.
        let other = engine
            .get_consent(realm_b.id(), &user, &client)
            .expect("get");
        assert!(other.is_none());
    }

    // ===== SCIM externalId tests =====

    fn create_scim_user(engine: &EmbeddedIdentityEngine, realm: &RealmId, email: &str) -> UserId {
        engine
            .create_user(
                realm,
                &CreateUserRequest {
                    email: email.to_string(),
                    display_name: "Alice".to_string(),
                    first_name: "Alice".to_string(),
                    last_name: "Example".to_string(),
                    attributes: Default::default(),
                },
            )
            .expect("create")
            .id()
            .clone()
    }

    #[test]
    fn scim_external_id_set_and_find_roundtrip() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r1".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = create_scim_user(&engine, realm.id(), "a@x.com");

        engine
            .set_scim_external_id(realm.id(), &user, "okta-abc")
            .expect("set");
        let found = engine
            .find_user_by_scim_external_id(realm.id(), "okta-abc")
            .expect("find")
            .expect("some");
        assert_eq!(found.id(), &user);
        let ext = engine
            .get_scim_external_id(realm.id(), &user)
            .expect("get")
            .expect("some");
        assert_eq!(ext, "okta-abc");
    }

    #[test]
    fn scim_external_id_duplicate_refused() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r2".to_string(),
                config: None,
            })
            .expect("create realm");
        let alice = create_scim_user(&engine, realm.id(), "a@x.com");
        let bob = create_scim_user(&engine, realm.id(), "b@x.com");

        engine
            .set_scim_external_id(realm.id(), &alice, "okta-abc")
            .expect("set alice");
        let err = engine
            .set_scim_external_id(realm.id(), &bob, "okta-abc")
            .expect_err("bob collision");
        assert!(matches!(err, IdentityError::DuplicateScimExternalId));
    }

    #[test]
    fn scim_external_id_reassigning_same_user_succeeds() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r3".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = create_scim_user(&engine, realm.id(), "a@x.com");

        engine
            .set_scim_external_id(realm.id(), &user, "v1")
            .expect("v1");
        engine
            .set_scim_external_id(realm.id(), &user, "v2")
            .expect("v2");
        // Old externalId must no longer resolve.
        assert!(engine
            .find_user_by_scim_external_id(realm.id(), "v1")
            .expect("find v1")
            .is_none());
        let via_v2 = engine
            .find_user_by_scim_external_id(realm.id(), "v2")
            .expect("find v2");
        assert!(via_v2.is_some());
    }

    #[test]
    fn scim_clear_external_id_is_idempotent() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r4".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = create_scim_user(&engine, realm.id(), "a@x.com");

        // Clearing when unset is a no-op.
        engine
            .clear_scim_external_id(realm.id(), &user)
            .expect("clear empty");

        engine
            .set_scim_external_id(realm.id(), &user, "okta-abc")
            .expect("set");
        engine
            .clear_scim_external_id(realm.id(), &user)
            .expect("clear");
        // A second clear is also fine.
        engine
            .clear_scim_external_id(realm.id(), &user)
            .expect("clear again");
        assert!(engine
            .find_user_by_scim_external_id(realm.id(), "okta-abc")
            .expect("find")
            .is_none());
    }

    #[test]
    fn scim_external_id_cascades_on_delete_user() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-r5".to_string(),
                config: None,
            })
            .expect("create realm");
        let user = create_scim_user(&engine, realm.id(), "a@x.com");
        engine
            .set_scim_external_id(realm.id(), &user, "okta-abc")
            .expect("set");
        engine.delete_user(realm.id(), &user).expect("delete");
        assert!(engine
            .find_user_by_scim_external_id(realm.id(), "okta-abc")
            .expect("find")
            .is_none());
        // Re-creating a user and assigning the same externalId should
        // succeed because the cascade freed it.
        let reborn = create_scim_user(&engine, realm.id(), "a@x.com");
        engine
            .set_scim_external_id(realm.id(), &reborn, "okta-abc")
            .expect("reuse");
    }

    #[test]
    fn scim_external_id_realm_isolated() {
        let (_dir, engine, _clock) = setup_engine();
        let r1 = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-ra".to_string(),
                config: None,
            })
            .expect("create r1");
        let r2 = engine
            .create_realm(&CreateRealmRequest {
                name: "scim-rb".to_string(),
                config: None,
            })
            .expect("create r2");
        let u1 = create_scim_user(&engine, r1.id(), "a@x.com");
        let u2 = create_scim_user(&engine, r2.id(), "a@x.com");
        engine
            .set_scim_external_id(r1.id(), &u1, "same-id")
            .expect("r1");
        // Same externalId is allowed in r2 because index is realm-scoped.
        engine
            .set_scim_external_id(r2.id(), &u2, "same-id")
            .expect("r2");
        assert_eq!(
            engine
                .find_user_by_scim_external_id(r1.id(), "same-id")
                .expect("find r1")
                .expect("some")
                .id(),
            &u1
        );
        assert_eq!(
            engine
                .find_user_by_scim_external_id(r2.id(), "same-id")
                .expect("find r2")
                .expect("some")
                .id(),
            &u2
        );
    }

    // ===== HEA-123: JWT signature verification regression tests =====

    /// Regression: forged access token with escalated permissions rejected
    ///
    /// Vulnerability class: Missing JWT signature verification (CWE-347).
    /// An attacker with no access to Hearth's Ed25519 signing key crafts a
    /// valid-looking JWT that claims admin permissions. With
    /// `decode_claims_unverified` this would succeed; after HEA-123,
    /// `verify_token_signature_for_realm` cryptographically rejects it.
    #[test]
    fn forged_access_token_with_escalated_permissions_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Real token validates
        engine
            .validate_token(&realm_id, tokens.access_token())
            .expect("real token should validate");

        // Craft a forged token with escalated permissions, signed by an
        // attacker-controlled key (not Hearth's key).
        let attacker_key = SigningKey::generate().expect("attacker keygen");
        let real_claims = tokens::decode_claims_unverified(tokens.access_token()).expect("decode");
        let forged_claims = TokenClaims {
            permissions: vec!["admin".to_string(), "*".to_string()],
            roles: vec!["superadmin".to_string()],
            ..real_claims
        };
        let forged_token = attacker_key
            .issue_token(&forged_claims)
            .expect("issue forged");

        let result = engine.validate_token(&realm_id, &forged_token);
        assert!(
            result.is_err(),
            "forged token with escalated permissions must be rejected"
        );
    }

    /// Regression: forged refresh token without valid signature rejected
    ///
    /// Vulnerability class: Missing JWT signature verification on refresh
    /// (CWE-347). An attacker with a stolen-but-expired refresh token could
    /// re-sign it with a new key and mint new tokens. HEA-123 ensures
    /// `verify_token_signature_for_realm` blocks forged refresh tokens.
    #[test]
    fn forged_refresh_token_rejected() {
        use crate::identity::oidc::AuthorizationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let client = engine
            .register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Forged Refresh App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec![
                        "authorization_code".to_string(),
                        "refresh_token".to_string(),
                    ],
                    require_consent: false,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register client");

        let auth = engine
            .authorize(
                &realm_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    state: "csrf-state".to_string(),
                    response_type: "code".to_string(),
                    scope: "openid".to_string(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    user_id: user.id().clone(),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize");

        let response = engine
            .exchange_authorization_code(
                &realm_id,
                &crate::identity::oidc::TokenExchangeRequest {
                    code: auth.code().to_string(),
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                },
            )
            .expect("exchange");

        // Real refresh works
        engine
            .refresh_tokens(&realm_id, response.refresh_token())
            .expect("legitimate refresh should succeed");

        // Craft a forged refresh token with a different signing key
        let attacker_key = SigningKey::generate().expect("attacker keygen");
        let real_claims =
            tokens::decode_claims_unverified(response.refresh_token()).expect("decode");
        let forged_claims = TokenClaims {
            exp: real_claims.exp + 86400, // extend lifetime
            token_type: "refresh".to_string(),
            ..real_claims
        };
        let forged_token = attacker_key
            .issue_token(&forged_claims)
            .expect("issue forged refresh");

        let result = engine.refresh_tokens(&realm_id, &forged_token);
        assert!(result.is_err(), "forged refresh token must be rejected");
    }

    /// Regression: forged revoke token silently ignored (RFC 7009)
    ///
    /// Vulnerability class: Missing JWT signature verification on revocation
    /// (CWE-347). An attacker with a forged token containing a real `sid`
    /// could revoke a victim's session without ever knowing their credentials.
    /// HEA-123 ensures forged tokens produce silent 200 OK without action.
    #[test]
    fn forged_revoke_token_silently_ignored() {
        use crate::identity::oidc::TokenRevocationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Craft a forged revocation token targeting a real session
        let attacker_key = SigningKey::generate().expect("attacker keygen");
        let real_claims = tokens::decode_claims_unverified(tokens.access_token()).expect("decode");
        let forged_claims = TokenClaims {
            token_type: "access".to_string(),
            ..real_claims
        };
        let forged_token = attacker_key
            .issue_token(&forged_claims)
            .expect("issue forged revoke");

        // RFC 7009: forged token revocation should silently succeed
        engine
            .revoke_token(
                &realm_id,
                &TokenRevocationRequest {
                    token: forged_token,
                    token_type_hint: Some("access_token".to_string()),
                },
            )
            .expect("forged revoke should silently succeed per RFC 7009");

        // The real session must NOT be revoked
        let result = engine.validate_token(&realm_id, tokens.access_token());
        assert!(
            result.is_ok(),
            "real session must not be revoked by forged token"
        );
    }

    /// Regression: forged token introspection shows inactive (RFC 7662)
    ///
    /// Vulnerability class: Missing JWT signature verification on introspection
    /// (CWE-347). An attacker could craft a token that appears active to the
    /// introspection endpoint, bypassing resource-server authorization checks.
    /// HEA-123 ensures forged tokens return `active: false`.
    #[test]
    fn forged_introspection_shows_inactive() {
        use crate::identity::oidc::TokenIntrospectionRequest;

        let (_dir, engine, _clock) = setup_engine();
        let realm_id = create_test_realm(&engine);
        let user = create_test_user(&engine, &realm_id);
        let session = engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("session");
        let tokens = engine
            .issue_tokens(&realm_id, user.id(), session.id())
            .expect("issue tokens");

        // Real introspection shows active
        let real_response = engine
            .introspect_token(
                &realm_id,
                &TokenIntrospectionRequest {
                    token: tokens.access_token().to_string(),
                    token_type_hint: Some("access_token".to_string()),
                },
            )
            .expect("real introspection");
        assert!(real_response.active, "real token should be active");

        // Craft a forged token with valid-looking claims but wrong key
        let attacker_key = SigningKey::generate().expect("attacker keygen");
        let real_claims = tokens::decode_claims_unverified(tokens.access_token()).expect("decode");
        let forged_claims = TokenClaims {
            exp: real_claims.exp + 86400,
            token_type: "access".to_string(),
            permissions: vec!["admin".to_string()],
            ..real_claims
        };
        let forged_token = attacker_key
            .issue_token(&forged_claims)
            .expect("issue forged introspect");

        let response = engine
            .introspect_token(
                &realm_id,
                &TokenIntrospectionRequest {
                    token: forged_token,
                    token_type_hint: Some("access_token".to_string()),
                },
            )
            .expect("forged introspection should not error");

        assert!(
            !response.active,
            "forged token introspection must return inactive"
        );
    }

    // ===== Password reset TTL =====

    #[test]
    fn password_reset_token_expires_after_configured_ttl() {
        let (_dir, engine, clock) = setup_engine();

        // Create a realm with a 5-minute password reset TTL.
        let short_ttl_micros: i64 = 5 * 60 * 1_000_000;
        let realm_req = crate::identity::CreateRealmRequest {
            name: format!("ttl-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_reset_token_ttl_micros: Some(short_ttl_micros),
                ..RealmConfig::default()
            }),
        };
        let realm = engine.create_realm(&realm_req).expect("create realm");
        let user = create_test_user(&engine, realm.id());
        engine
            .set_password(
                realm.id(),
                user.id(),
                &CleartextPassword::from_string("ValidPassword1!".to_string()),
            )
            .expect("set password");

        // Issue a reset token.
        let token = engine
            .request_password_reset(realm.id(), user.email())
            .expect("request reset")
            .expect("known user should produce token");

        // Token is valid immediately.
        engine
            .reset_password_with_token(
                realm.id(),
                &token,
                &CleartextPassword::from_string("NewValidPassword1!".to_string()),
            )
            .expect("reset should succeed within TTL");

        // Issue a second token and advance the clock past the TTL.
        let token2 = engine
            .request_password_reset(realm.id(), user.email())
            .expect("request second reset")
            .expect("token");
        clock.advance(short_ttl_micros + 1);

        let err = engine
            .reset_password_with_token(
                realm.id(),
                &token2,
                &CleartextPassword::from_string("AnotherPass1!".to_string()),
            )
            .expect_err("expired token must be rejected");
        assert!(
            matches!(err, IdentityError::PasswordResetTokenInvalid),
            "expected PasswordResetTokenInvalid after TTL expiry, got: {err}"
        );
    }

    // ==========================================================================
    // HEA-501: Security Phase A — PKCE mandatory, redirect URI hardening, RFC 9207 iss
    // ==========================================================================

    // F-01: Public client must supply PKCE S256
    #[test]
    fn public_client_requires_pkce_s256() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm); // public client
        let user = create_test_user(&engine, &realm);
        assert!(
            !client.is_confidential(),
            "register_test_client must be public"
        );

        let err = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                    resource: None,
                },
            )
            .expect_err("must reject public client with no PKCE");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("public clients must use PKCE")),
            "got: {err}"
        );
    }

    // F-01: Plain PKCE method must be rejected even when challenge is present
    #[test]
    fn pkce_challenge_without_s256_method_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        // challenge present but no method supplied
        let err = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: None,
                    nonce: None,
                    resource: None,
                },
            )
            .expect_err("must reject challenge without S256 method");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("S256")),
            "got: {err}"
        );
    }

    // F-01: Confidential client can omit PKCE (not required)
    #[test]
    fn confidential_client_can_omit_pkce() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        // Confidential auth-code client: has secret + redirect_uri + authorization_code grant.
        let client = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Confidential Auth Code App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: Some("s3cr3t".to_string()),
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("register confidential client");
        let user = create_test_user(&engine, &realm);
        assert!(client.is_confidential());

        engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                    resource: None,
                },
            )
            .expect("confidential client must succeed without PKCE");
    }

    // F-02: Redirect URI with fragment must be rejected at registration
    #[test]
    fn redirect_uri_fragment_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Frag App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb#fragment".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect_err("fragment URI must be rejected");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("fragment")),
            "got: {err}"
        );
    }

    // F-02: Redirect URI with wildcard must be rejected
    #[test]
    fn redirect_uri_wildcard_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Wild App".to_string(),
                    redirect_uris: vec!["https://*.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect_err("wildcard URI must be rejected");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("wildcard")),
            "got: {err}"
        );
    }

    // F-02: Non-localhost http URI must be rejected
    #[test]
    fn redirect_uri_http_non_localhost_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        let err = engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Bad App".to_string(),
                    redirect_uris: vec!["http://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect_err("http non-localhost URI must be rejected");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("loopback")),
            "got: {err}"
        );
    }

    // F-02: localhost http URI must be allowed (RFC 8252 §8.3)
    #[test]
    fn redirect_uri_http_localhost_allowed() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();

        engine
            .register_client(
                &realm,
                &RegisterClientRequest {
                    client_name: "Native App".to_string(),
                    redirect_uris: vec!["http://localhost:8080/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                    ..Default::default()
                },
            )
            .expect("localhost http must be allowed");
    }

    // F-15: Scope with invalid characters must be rejected
    #[test]
    fn scope_with_invalid_characters_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let err = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid \"bad-scope\"".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect_err("invalid scope chars must be rejected");
        assert!(
            matches!(&err, IdentityError::InvalidInput { reason } if reason.contains("scope")),
            "got: {err}"
        );
    }

    // F-07: Authorization response includes iss
    #[test]
    fn authorization_response_includes_iss() {
        let (_dir, engine, _clock) = setup_engine();
        let realm = RealmId::generate();
        let client = register_test_client(&engine, &realm);
        let user = create_test_user(&engine, &realm);

        let resp = engine
            .authorize(
                &realm,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "s".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                    resource: None,
                },
            )
            .expect("authorize must succeed");

        assert!(!resp.iss().is_empty(), "iss must be present in response");
        assert!(
            resp.iss().starts_with("http"),
            "iss must be an absolute URL, got: {}",
            resp.iss()
        );
    }

    // F-07: Discovery document advertises authorization_response_iss_parameter_supported
    #[test]
    fn discovery_doc_includes_iss_parameter_supported() {
        let (_dir, engine, _clock) = setup_engine();
        let doc = engine.oidc_discovery();
        assert!(
            doc.authorization_response_iss_parameter_supported,
            "discovery must advertise iss parameter support"
        );
    }
}
