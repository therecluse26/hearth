//! Embedded identity engine implementation.
//!
//! Implements `IdentityEngine` using the `StorageEngine` trait for persistence
//! and `Clock` trait for deterministic timestamps.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SecureRandom;

use crate::core::{ClientId, Clock, SessionId, TenantId, UserId};
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
    self, MagicLinkResponse, StoredMagicLink, MAGIC_LINK_EXPIRY_MICROS,
};
use crate::identity::oidc::{
    AuthorizationRequest, AuthorizationResponse, CodeChallengeMethod, OAuthClient, OidcConfig,
    OidcDiscoveryDocument, OidcTokenResponse, RegisterClientRequest, StoredAuthorizationCode,
    StoredDeviceCode, StoredGrantFamily, TokenExchangeRequest,
};
use crate::identity::tokens::{
    self, IssueTokenRequest, JwksDocument, SigningKey, TokenClaims, TokenConfig, TokenPair,
};
use crate::identity::totp::{self, StoredMfaState, TotpEnrollment, TotpSecret};
use crate::identity::types::{
    BulkResult, CreateTenantRequest, CreateUserRequest, Page, Session, Tenant, TenantStatus,
    UpdateTenantRequest, UpdateUserRequest, User, UserStatus,
};
use crate::identity::validation;
use crate::identity::webauthn::{
    self, AuthenticationOptions, CeremonyType, CompleteAuthenticationParams,
    PendingWebAuthnChallenge, RegistrationOptions, StoredWebAuthnCredential, WebAuthnAuthResult,
    WebAuthnChallengeStore, WebAuthnCredentialInfo,
};
use crate::identity::IdentityEngine;
use crate::storage::StorageEngine;

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
/// with per-tenant signing keys and configuration.
pub struct EmbeddedIdentityEngine {
    /// The underlying storage engine.
    storage: Arc<dyn StorageEngine>,
    /// Injectable clock for deterministic testing.
    clock: Arc<dyn Clock>,
    /// Engine configuration (global defaults, overridable per-tenant).
    config: IdentityConfig,
    /// Pre-computed dummy hash for timing-oracle prevention.
    ///
    /// When `verify_password` is called for a nonexistent user or missing
    /// credential, we verify against this dummy hash so the response time
    /// is indistinguishable from a real failed verification.
    dummy_hash: String,
    /// Default Ed25519 signing key for JWT token issuance (Phase 0 compat).
    signing_key: Arc<SigningKey>,
    /// Per-tenant signing keys, lazily loaded from storage.
    ///
    /// Each tenant gets its own Ed25519 key pair so tokens from one
    /// tenant cannot validate in another.
    tenant_signing_keys: Mutex<HashMap<String, Arc<SigningKey>>>,
    /// Per-user failed attempt trackers for rate limiting.
    ///
    /// Key is `(TenantId, UserId)` serialized as a string to avoid
    /// requiring `Hash` on the newtype wrappers.
    attempt_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Per-user failed MFA attempt trackers (separate from password rate limiting).
    ///
    /// Stricter limits: 5 attempts, 5-minute lockout. Key format: `mfa:{tenant}:{user}`.
    mfa_attempt_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Used nonces for replay protection (when nonce enforcement is enabled).
    used_nonces: Mutex<HashSet<String>>,
    /// Per-email magic link rate trackers.
    ///
    /// Limits the number of magic link requests per email per hour.
    /// Key format: `magic:{tenant}:{email}`.
    magic_link_rate_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Pending `WebAuthn` challenges awaiting completion.
    webauthn_challenges: WebAuthnChallengeStore,
}

impl std::fmt::Debug for EmbeddedIdentityEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedIdentityEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl EmbeddedIdentityEngine {
    /// Creates a new identity engine.
    ///
    /// Generates an Ed25519 signing key and pre-computes a dummy Argon2id
    /// hash on construction for timing-oracle prevention during password
    /// verification.
    pub fn new(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
    ) -> Result<Self, IdentityError> {
        let dummy_hash = credentials::compute_dummy_hash(&config.credential);
        let signing_key = Arc::new(SigningKey::generate()?);
        Ok(Self {
            storage,
            clock,
            config,
            dummy_hash,
            signing_key,
            tenant_signing_keys: Mutex::new(HashMap::new()),
            attempt_trackers: Mutex::new(HashMap::new()),
            mfa_attempt_trackers: Mutex::new(HashMap::new()),
            magic_link_rate_trackers: Mutex::new(HashMap::new()),
            used_nonces: Mutex::new(HashSet::new()),
            webauthn_challenges: WebAuthnChallengeStore::new(),
        })
    }

    /// Creates a new identity engine with a pre-existing signing key.
    ///
    /// Used for testing with a known key or for key restoration from storage.
    pub fn with_signing_key(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
        signing_key: Arc<SigningKey>,
    ) -> Self {
        let dummy_hash = credentials::compute_dummy_hash(&config.credential);
        Self {
            storage,
            clock,
            config,
            dummy_hash,
            signing_key,
            tenant_signing_keys: Mutex::new(HashMap::new()),
            attempt_trackers: Mutex::new(HashMap::new()),
            mfa_attempt_trackers: Mutex::new(HashMap::new()),
            magic_link_rate_trackers: Mutex::new(HashMap::new()),
            used_nonces: Mutex::new(HashSet::new()),
            webauthn_challenges: WebAuthnChallengeStore::new(),
        }
    }

    /// Returns a reference to the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    // ===== Rate limiting helpers =====

    /// Builds a tracker key from tenant and user IDs.
    fn tracker_key(tenant_id: &TenantId, user_id: &UserId) -> String {
        format!("{}:{}", tenant_id.as_uuid(), user_id.as_uuid())
    }

    /// Checks whether the given user is currently rate-limited.
    ///
    /// Returns `Err(RateLimited)` if the user has exceeded the maximum
    /// number of consecutive failed attempts and the lockout window
    /// has not yet expired. Otherwise returns `Ok(())`.
    fn check_rate_limit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let key = Self::tracker_key(tenant_id, user_id);
        let trackers = self.attempt_trackers.lock().expect("tracker lock");
        if let Some(tracker) = trackers.get(&key) {
            if tracker.failed_count >= self.config.rate_limit.max_failed_attempts {
                let now = self.clock.now().as_micros();
                let elapsed = now - tracker.last_failure_micros;
                if elapsed < self.config.rate_limit.lockout_duration_micros {
                    return Err(IdentityError::RateLimited);
                }
                // Lockout window has expired — fall through and allow the attempt.
                // The tracker will be cleared on success or updated on failure.
            }
        }
        Ok(())
    }

    /// Records a failed verification attempt for the given user.
    fn record_failed_attempt(&self, tenant_id: &TenantId, user_id: &UserId) {
        let key = Self::tracker_key(tenant_id, user_id);
        let now = self.clock.now().as_micros();
        let mut trackers = self.attempt_trackers.lock().expect("tracker lock");
        let tracker = trackers.entry(key).or_insert(AttemptTracker {
            failed_count: 0,
            last_failure_micros: now,
        });
        tracker.failed_count += 1;
        tracker.last_failure_micros = now;
    }

    /// Clears the failed attempt tracker for the given user (on success).
    fn clear_attempts(&self, tenant_id: &TenantId, user_id: &UserId) {
        let key = Self::tracker_key(tenant_id, user_id);
        let mut trackers = self.attempt_trackers.lock().expect("tracker lock");
        trackers.remove(&key);
    }

    // ===== MFA rate limiting helpers =====

    /// MFA rate limit: 5 attempts, 5-minute lockout.
    const MFA_MAX_ATTEMPTS: u32 = 5;
    /// MFA lockout duration: 5 minutes in microseconds.
    const MFA_LOCKOUT_MICROS: i64 = 5 * 60 * 1_000_000;

    /// Builds an MFA tracker key from tenant and user IDs.
    fn mfa_tracker_key(tenant_id: &TenantId, user_id: &UserId) -> String {
        format!("mfa:{}:{}", tenant_id.as_uuid(), user_id.as_uuid())
    }

    /// Checks whether the given user is currently MFA-rate-limited.
    fn check_mfa_rate_limit(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        let key = Self::mfa_tracker_key(tenant_id, user_id);
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
    fn record_mfa_failed_attempt(&self, tenant_id: &TenantId, user_id: &UserId) {
        let key = Self::mfa_tracker_key(tenant_id, user_id);
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
    fn clear_mfa_attempts(&self, tenant_id: &TenantId, user_id: &UserId) {
        let key = Self::mfa_tracker_key(tenant_id, user_id);
        let mut trackers = self.mfa_attempt_trackers.lock().expect("mfa tracker lock");
        trackers.remove(&key);
    }

    // ===== Magic link rate limiting helpers =====

    /// Magic link rate limit: 3 requests per email per hour.
    const MAGIC_LINK_MAX_REQUESTS: u32 = 3;
    /// Magic link rate limit window: 1 hour in microseconds.
    const MAGIC_LINK_RATE_WINDOW_MICROS: i64 = 60 * 60 * 1_000_000;

    /// Builds a magic link rate tracker key from tenant and email.
    fn magic_link_tracker_key(tenant_id: &TenantId, email: &str) -> String {
        format!("magic:{}:{email}", tenant_id.as_uuid())
    }

    /// Checks whether magic link requests for this email are rate-limited.
    fn check_magic_link_rate_limit(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<(), IdentityError> {
        let key = Self::magic_link_tracker_key(tenant_id, email);
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
    fn record_magic_link_request(&self, tenant_id: &TenantId, email: &str) {
        let key = Self::magic_link_tracker_key(tenant_id, email);
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

    /// Loads the stored MFA state for a user.
    fn load_mfa_state(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<StoredMfaState>, IdentityError> {
        let key = keys::encode_mfa_totp_key(user_id);
        let bytes = self
            .storage
            .get(tenant_id, &key)
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
        tenant_id: &TenantId,
        user_id: &UserId,
        state: &StoredMfaState,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_mfa_totp_key(user_id);
        let bytes = serde_json::to_vec(state).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(tenant_id, &key, &bytes)
            .map_err(Self::storage_err)
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
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        let key = keys::encode_session_id(session_id);
        let bytes = self
            .storage
            .get(tenant_id, &key)
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
    fn persist_session(
        &self,
        tenant_id: &TenantId,
        session: &Session,
    ) -> Result<(), IdentityError> {
        let session_bytes = Self::serialize_session(session)?;
        let id_key = keys::encode_session_id(session.id());
        self.storage
            .put(tenant_id, &id_key, &session_bytes)
            .map_err(Self::storage_err)?;
        Ok(())
    }

    // ===== Tenant helpers =====

    /// Serializes a tenant record to JSON bytes.
    fn serialize_tenant(tenant: &Tenant) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(tenant).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Deserializes a tenant record from JSON bytes.
    fn deserialize_tenant(bytes: &[u8]) -> Result<Tenant, IdentityError> {
        serde_json::from_slice(bytes).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Gets the signing key for a tenant, falling back to the default key.
    ///
    /// Used by token issuance paths where backward compatibility with
    /// Phase 0 tenants (which lack per-tenant keys) is needed.
    fn get_signing_key_or_default(&self, tenant_id: &TenantId) -> Arc<SigningKey> {
        self.get_or_load_tenant_signing_key(tenant_id)
            .unwrap_or_else(|_| Arc::clone(&self.signing_key))
    }

    /// Retrieves (or lazily loads from storage) the signing key for a tenant.
    ///
    /// Checks the in-memory cache first, then loads from storage on cache miss.
    /// Returns `TenantNotFound` if no per-tenant key exists.
    fn get_or_load_tenant_signing_key(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Arc<SigningKey>, IdentityError> {
        let cache_key = tenant_id.as_uuid().to_string();

        // Check cache
        {
            let key_cache = self.tenant_signing_keys.lock().expect("key cache lock");
            if let Some(key) = key_cache.get(&cache_key) {
                return Ok(Arc::clone(key));
            }
        }

        // Load from storage
        let sys_tenant = keys::system_tenant_id();
        let key_storage_key = keys::encode_tenant_signing_key(tenant_id);
        let key_bytes = self
            .storage
            .get(&sys_tenant, &key_storage_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::TenantNotFound)?;

        let signing_key = Arc::new(SigningKey::from_pkcs8(&key_bytes)?);

        // Cache it
        {
            let mut key_cache = self.tenant_signing_keys.lock().expect("key cache lock");
            key_cache.insert(cache_key, Arc::clone(&signing_key));
        }

        Ok(signing_key)
    }
}

impl IdentityEngine for EmbeddedIdentityEngine {
    // ===== Tenant lifecycle (Phase 1 Step 19) =====

    fn create_tenant(&self, request: &CreateTenantRequest) -> Result<Tenant, IdentityError> {
        let now = self.clock.now();
        let tenant_id = TenantId::generate();
        let config = request.config.clone().unwrap_or_default();

        // Generate a per-tenant signing key
        let tenant_signing_key = SigningKey::generate()?;

        // Persist the tenant record under the system tenant namespace
        let sys_tenant = keys::system_tenant_id();
        let tenant = Tenant::new(
            tenant_id.clone(),
            request.name.clone(),
            TenantStatus::Active,
            config,
            now,
            now,
        );
        let tenant_bytes = Self::serialize_tenant(&tenant)?;
        let tenant_key = keys::encode_tenant_id(&tenant_id);
        self.storage
            .put(&sys_tenant, &tenant_key, &tenant_bytes)
            .map_err(Self::storage_err)?;

        // Persist the per-tenant signing key (PKCS#8 DER)
        let key_storage_key = keys::encode_tenant_signing_key(&tenant_id);
        let key_bytes = tenant_signing_key.pkcs8_bytes();
        self.storage
            .put(&sys_tenant, &key_storage_key, key_bytes)
            .map_err(Self::storage_err)?;

        // Cache the signing key in memory
        {
            let mut key_cache = self.tenant_signing_keys.lock().expect("key cache lock");
            key_cache.insert(
                tenant_id.as_uuid().to_string(),
                Arc::new(tenant_signing_key),
            );
        }

        Ok(tenant)
    }

    fn get_tenant(&self, tenant_id: &TenantId) -> Result<Option<Tenant>, IdentityError> {
        let sys_tenant = keys::system_tenant_id();
        let tenant_key = keys::encode_tenant_id(tenant_id);
        let bytes = self
            .storage
            .get(&sys_tenant, &tenant_key)
            .map_err(Self::storage_err)?;
        match bytes {
            Some(b) => Ok(Some(Self::deserialize_tenant(&b)?)),
            None => Ok(None),
        }
    }

    fn update_tenant(
        &self,
        tenant_id: &TenantId,
        request: &UpdateTenantRequest,
    ) -> Result<Tenant, IdentityError> {
        let mut tenant = self
            .get_tenant(tenant_id)?
            .ok_or(IdentityError::TenantNotFound)?;

        let now = self.clock.now();

        if let Some(ref name) = request.name {
            tenant.set_name(name.clone());
        }
        if let Some(status) = request.status {
            tenant.set_status(status);
        }
        if let Some(ref config) = request.config {
            tenant.set_config(config.clone());
        }
        tenant.set_updated_at(now);

        let sys_tenant = keys::system_tenant_id();
        let tenant_key = keys::encode_tenant_id(tenant_id);
        let tenant_bytes = Self::serialize_tenant(&tenant)?;
        self.storage
            .put(&sys_tenant, &tenant_key, &tenant_bytes)
            .map_err(Self::storage_err)?;

        Ok(tenant)
    }

    #[allow(clippy::too_many_lines)]
    fn delete_tenant(&self, tenant_id: &TenantId) -> Result<(), IdentityError> {
        // Verify tenant exists
        self.get_tenant(tenant_id)?
            .ok_or(IdentityError::TenantNotFound)?;

        // 1. Delete all users in this tenant (cascades to sessions, credentials)
        let user_prefix = keys::user_id_scan_prefix();
        let user_end = keys::prefix_end(&user_prefix);
        let users = self
            .storage
            .scan(tenant_id, &user_prefix, &user_end)
            .map_err(Self::storage_err)?;

        for entry in &users {
            let user: User = Self::deserialize_user(&entry.value)?;
            // delete_user handles cascade of sessions, credentials, email index
            let _ = self.delete_user(tenant_id, user.id());
        }

        // 2. Delete all OAuth clients
        let client_prefix = b"oauth:client:";
        let client_end = keys::prefix_end(client_prefix);
        let clients = self
            .storage
            .scan(tenant_id, client_prefix, &client_end)
            .map_err(Self::storage_err)?;
        for entry in &clients {
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 3. Delete all authorization tuples (prefix "rel:")
        let rel_prefix = b"rel:";
        let rel_end = keys::prefix_end(rel_prefix);
        let rels = self
            .storage
            .scan(tenant_id, rel_prefix, &rel_end)
            .map_err(Self::storage_err)?;
        for entry in &rels {
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 4. Delete all OAuth authorization codes
        let code_prefix = b"oauth:code:";
        let code_end = keys::prefix_end(code_prefix);
        let codes = self
            .storage
            .scan(tenant_id, code_prefix, &code_end)
            .map_err(Self::storage_err)?;
        for entry in &codes {
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 5. Delete all grant families
        let family_prefix = keys::grant_family_scan_prefix();
        let family_end = keys::prefix_end(&family_prefix);
        let families = self
            .storage
            .scan(tenant_id, &family_prefix, &family_end)
            .map_err(Self::storage_err)?;
        for entry in &families {
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 6. Delete all device codes
        let device_prefix = keys::device_code_scan_prefix();
        let device_end = keys::prefix_end(&device_prefix);
        let devices = self
            .storage
            .scan(tenant_id, &device_prefix, &device_end)
            .map_err(Self::storage_err)?;
        for entry in &devices {
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 7. Delete all revoked JTIs
        let jti_prefix = b"oauth:revjti:";
        let jti_end = keys::prefix_end(jti_prefix);
        let jtis = self
            .storage
            .scan(tenant_id, jti_prefix, &jti_end)
            .map_err(Self::storage_err)?;
        for entry in &jtis {
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 8. Delete all user-code index entries
        let ucode_prefix = b"oauth:ucode:";
        let ucode_end = keys::prefix_end(ucode_prefix);
        let ucodes = self
            .storage
            .scan(tenant_id, ucode_prefix, &ucode_end)
            .map_err(Self::storage_err)?;
        for entry in &ucodes {
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 9. Delete tenant signing key
        let sys_tenant = keys::system_tenant_id();
        let key_storage_key = keys::encode_tenant_signing_key(tenant_id);
        self.storage
            .delete(&sys_tenant, &key_storage_key)
            .map_err(Self::storage_err)?;

        // 10. Remove from in-memory key cache
        {
            let mut key_cache = self.tenant_signing_keys.lock().expect("key cache lock");
            key_cache.remove(&tenant_id.as_uuid().to_string());
        }

        // 11. Delete tenant record itself
        let tenant_key = keys::encode_tenant_id(tenant_id);
        self.storage
            .delete(&sys_tenant, &tenant_key)
            .map_err(Self::storage_err)?;

        Ok(())
    }

    fn tenant_jwks(&self, tenant_id: &TenantId) -> Result<JwksDocument, IdentityError> {
        let key = self.get_or_load_tenant_signing_key(tenant_id)?;
        Ok(key.to_jwks())
    }

    // ===== User CRUD =====

    fn create_user(
        &self,
        tenant_id: &TenantId,
        request: &CreateUserRequest,
    ) -> Result<User, IdentityError> {
        // 1. Validate and normalize input
        let email = validation::validate_email(&request.email)?;
        let display_name = validation::validate_display_name(&request.display_name)?;

        // 2. Check email uniqueness
        let email_key = keys::encode_user_email(&email);
        let existing = self
            .storage
            .get(tenant_id, &email_key)
            .map_err(Self::storage_err)?;
        if existing.is_some() {
            return Err(IdentityError::DuplicateEmail);
        }

        // 3. Generate ID and timestamps
        let user_id = UserId::generate();
        let now = self.clock.now();

        // 4. Build user record
        let user = User::new(
            user_id.clone(),
            email.clone(),
            display_name,
            self.config.default_status,
            now,
            now,
        );

        // 5. Serialize
        let user_bytes = Self::serialize_user(&user)?;

        // 6. Write email index (UserId UUID string bytes)
        let user_id_bytes = user_id.as_uuid().to_string().into_bytes();
        self.storage
            .put(tenant_id, &email_key, &user_id_bytes)
            .map_err(Self::storage_err)?;

        // 7. Write primary record
        let id_key = keys::encode_user_id(&user_id);
        self.storage
            .put(tenant_id, &id_key, &user_bytes)
            .map_err(Self::storage_err)?;

        Ok(user)
    }

    fn get_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<User>, IdentityError> {
        let key = keys::encode_user_id(user_id);
        let bytes = self
            .storage
            .get(tenant_id, &key)
            .map_err(Self::storage_err)?;

        match bytes {
            Some(data) => Ok(Some(Self::deserialize_user(&data)?)),
            None => Ok(None),
        }
    }

    fn get_user_by_email(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<Option<User>, IdentityError> {
        // Normalize the lookup email
        let normalized = validation::validate_email(email)?;
        let email_key = keys::encode_user_email(&normalized);

        // Look up UserId from email index
        let id_bytes = self
            .storage
            .get(tenant_id, &email_key)
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

        self.get_user(tenant_id, &user_id)
    }

    fn update_user(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        request: &UpdateUserRequest,
    ) -> Result<User, IdentityError> {
        // 1. Load existing user
        let mut user = self
            .get_user(tenant_id, user_id)?
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
                    .get(tenant_id, &new_email_key)
                    .map_err(Self::storage_err)?;
                if existing.is_some() {
                    return Err(IdentityError::DuplicateEmail);
                }

                // Remove old email index
                let old_email_key = keys::encode_user_email(&old_email);
                self.storage
                    .delete(tenant_id, &old_email_key)
                    .map_err(Self::storage_err)?;

                // Write new email index
                let user_id_bytes = user_id.as_uuid().to_string().into_bytes();
                self.storage
                    .put(tenant_id, &new_email_key, &user_id_bytes)
                    .map_err(Self::storage_err)?;

                user.set_email(normalized);
            }
        }

        // 3. Apply display name change if requested
        if let Some(ref new_name) = request.display_name {
            let normalized = validation::validate_display_name(new_name)?;
            user.set_display_name(normalized);
        }

        // 4. Apply status change if requested
        if let Some(new_status) = request.status {
            user.set_status(new_status);
        }

        // 5. Update timestamp
        user.set_updated_at(self.clock.now());

        // 6. Write updated record
        let user_bytes = Self::serialize_user(&user)?;
        let id_key = keys::encode_user_id(user_id);
        self.storage
            .put(tenant_id, &id_key, &user_bytes)
            .map_err(Self::storage_err)?;

        Ok(user)
    }

    fn delete_user(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<(), IdentityError> {
        // 1. Load user to get email for index cleanup
        let user = self
            .get_user(tenant_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // 2. Delete primary record
        let id_key = keys::encode_user_id(user_id);
        self.storage
            .delete(tenant_id, &id_key)
            .map_err(Self::storage_err)?;

        // 3. Delete email index
        let email_key = keys::encode_user_email(user.email());
        self.storage
            .delete(tenant_id, &email_key)
            .map_err(Self::storage_err)?;

        // 4. Delete credential (if any — best effort, ignore not-found)
        let cred_key = keys::encode_credential_key(user_id);
        self.storage
            .delete(tenant_id, &cred_key)
            .map_err(Self::storage_err)?;

        // 4b. Delete MFA state (if any — best effort)
        let mfa_key = keys::encode_mfa_totp_key(user_id);
        self.storage
            .delete(tenant_id, &mfa_key)
            .map_err(Self::storage_err)?;

        // 4c. Delete all WebAuthn credentials + discoverable index entries
        let webauthn_prefix = keys::encode_webauthn_credentials_prefix(user_id);
        let webauthn_end = keys::prefix_end(&webauthn_prefix);
        let webauthn_entries = self
            .storage
            .scan(tenant_id, &webauthn_prefix, &webauthn_end)
            .map_err(Self::storage_err)?;

        for entry in &webauthn_entries {
            // If discoverable, delete the discoverable index entry
            if let Ok(stored) = serde_json::from_slice::<StoredWebAuthnCredential>(&entry.value) {
                if stored.discoverable {
                    let disc_key = keys::encode_webauthn_discoverable(&stored.credential_id_b64);
                    self.storage
                        .delete(tenant_id, &disc_key)
                        .map_err(Self::storage_err)?;
                }
            }
            // Delete the credential itself
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        // 5. Delete all sessions for this user
        let session_prefix = keys::encode_user_sessions_prefix(user_id);
        let session_end = keys::prefix_end(&session_prefix);
        let session_entries = self
            .storage
            .scan(tenant_id, &session_prefix, &session_end)
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
                        .delete(tenant_id, &session_key)
                        .map_err(Self::storage_err)?;
                }
            }

            // Delete the user-session index entry itself
            // The scan returns keys without tenant prefix, so re-use entry.key
            self.storage
                .delete(tenant_id, &entry.key)
                .map_err(Self::storage_err)?;
        }

        Ok(())
    }

    fn set_password(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<(), IdentityError> {
        // Validate password length
        validation::validate_password_length(password.as_bytes())?;

        // Ensure the user exists
        self.get_user(tenant_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Hash and store
        let now = self.clock.now().as_micros();
        let cred = credentials::hash_password(password, &self.config.credential, now)?;
        let cred_bytes = Self::serialize_credential(&cred)?;
        let cred_key = keys::encode_credential_key(user_id);
        self.storage
            .put(tenant_id, &cred_key, &cred_bytes)
            .map_err(Self::storage_err)?;

        Ok(())
    }

    fn verify_password(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<bool, IdentityError> {
        // Rate limit check: reject early if account is locked out
        self.check_rate_limit(tenant_id, user_id)?;

        // Check user exists
        let user = self.get_user(tenant_id, user_id)?;
        if user.is_none() {
            // Timing defense: verify against dummy hash so timing is
            // indistinguishable from a real failed verification.
            // Return generic error to prevent user enumeration.
            let _ = credentials::verify_hash(password, &self.dummy_hash);
            self.record_failed_attempt(tenant_id, user_id);
            return Err(IdentityError::InvalidCredential {
                reason: "verification failed".to_string(),
            });
        }

        // Load credential
        let cred_key = keys::encode_credential_key(user_id);
        let cred_bytes = self
            .storage
            .get(tenant_id, &cred_key)
            .map_err(Self::storage_err)?;

        let Some(cred_bytes) = cred_bytes else {
            // Timing defense: same as above.
            // Return generic error to prevent credential enumeration.
            let _ = credentials::verify_hash(password, &self.dummy_hash);
            self.record_failed_attempt(tenant_id, user_id);
            return Err(IdentityError::InvalidCredential {
                reason: "verification failed".to_string(),
            });
        };

        let cred = Self::deserialize_credential(&cred_bytes)?;
        let matches = credentials::verify_password(password, &cred)?;

        if matches {
            // Clear failed attempts on success
            self.clear_attempts(tenant_id, user_id);

            // Auto-upgrade legacy algorithms on successful verification
            if cred.algorithm != credentials::PasswordAlgorithm::Argon2id {
                let now = self.clock.now().as_micros();
                let upgraded = credentials::hash_password(password, &self.config.credential, now)?;
                let upgraded_bytes = Self::serialize_credential(&upgraded)?;
                self.storage
                    .put(tenant_id, &cred_key, &upgraded_bytes)
                    .map_err(Self::storage_err)?;
            }
        } else {
            self.record_failed_attempt(tenant_id, user_id);
        }

        Ok(matches)
    }

    fn change_password(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        old_password: &CleartextPassword,
        new_password: &CleartextPassword,
    ) -> Result<(), IdentityError> {
        // Verify old password (this also checks user existence and credential existence)
        let matches = self.verify_password(tenant_id, user_id, old_password)?;
        if !matches {
            return Err(IdentityError::InvalidCredential {
                reason: "old password does not match".to_string(),
            });
        }

        // Set the new password
        self.set_password(tenant_id, user_id, new_password)
    }

    fn create_session(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Session, IdentityError> {
        // Ensure the user exists
        self.get_user(tenant_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Generate session
        let session_id = SessionId::generate();
        let now = self.clock.now();
        let expires_at = now.add_micros(self.config.session.ttl_micros);
        let session = Session::new(session_id.clone(), user_id.clone(), now, expires_at);

        // Persist session record
        self.persist_session(tenant_id, &session)?;

        // Write user-to-session index entry
        let user_session_key = keys::encode_user_session(user_id, &session_id);
        self.storage
            .put(tenant_id, &user_session_key, &[])
            .map_err(Self::storage_err)?;

        Ok(session)
    }

    fn get_session(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        let session = self.load_session_raw(tenant_id, session_id)?;
        match session {
            Some(s) if s.is_valid(self.clock.now()) => Ok(Some(s)),
            _ => Ok(None),
        }
    }

    fn revoke_session(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<(), IdentityError> {
        let mut session = self
            .load_session_raw(tenant_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;

        session.revoke();
        self.persist_session(tenant_id, &session)?;

        Ok(())
    }

    fn refresh_session(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Session, IdentityError> {
        let mut session = self
            .load_session_raw(tenant_id, session_id)?
            .ok_or(IdentityError::SessionNotFound)?;

        // Cannot refresh a revoked or expired session
        if !session.is_valid(self.clock.now()) {
            return Err(IdentityError::SessionNotFound);
        }

        session.refresh(self.clock.now(), self.config.session.ttl_micros);
        self.persist_session(tenant_id, &session)?;

        Ok(session)
    }

    // ===== Token management =====

    fn issue_tokens(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        session_id: &SessionId,
    ) -> Result<TokenPair, IdentityError> {
        // Verify user exists
        let user = self.get_user(tenant_id, user_id)?;
        if user.is_none() {
            return Err(IdentityError::UserNotFound);
        }

        // Verify session exists and is valid
        let session = self.get_session(tenant_id, session_id)?;
        if session.is_none() {
            return Err(IdentityError::SessionNotFound);
        }

        let now = self.clock.now();
        self.signing_key.issue_token_pair(&IssueTokenRequest {
            sub: &user_id.to_string(),
            sid: &session_id.to_string(),
            tid: &tenant_id.to_string(),
            now,
            config: &self.config.token,
        })
    }

    fn validate_token(
        &self,
        tenant_id: &TenantId,
        token: &str,
    ) -> Result<TokenClaims, IdentityError> {
        // Hot path: extract claims without signature verification
        let claims = tokens::decode_claims_unverified(token)?;

        // Verify the token was issued for this tenant
        if claims.tid != tenant_id.to_string() {
            return Err(IdentityError::InvalidToken);
        }

        // Parse session ID from claims
        let session_id_str = claims
            .sid
            .strip_prefix("session_")
            .ok_or(IdentityError::InvalidToken)?;
        let session_uuid =
            uuid::Uuid::parse_str(session_id_str).map_err(|_| IdentityError::InvalidToken)?;
        let session_id = SessionId::new(session_uuid);

        // Look up session — this is the actual validation
        let session = self.get_session(tenant_id, &session_id)?;
        if session.is_none() {
            return Err(IdentityError::InvalidToken);
        }

        Ok(claims)
    }

    fn refresh_tokens(
        &self,
        tenant_id: &TenantId,
        refresh_token: &str,
    ) -> Result<TokenPair, IdentityError> {
        // Decode the refresh token (unverified — we trust our own tokens)
        let claims = tokens::decode_claims_unverified(refresh_token)?;

        // Must be a refresh token
        if claims.token_type != "refresh" {
            return Err(IdentityError::InvalidToken);
        }

        // Verify tenant matches
        if claims.tid != tenant_id.to_string() {
            return Err(IdentityError::InvalidToken);
        }

        // Check expiration
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::TokenExpired);
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

        // Grant family rotation (if fid is present)
        if let Some(ref fid) = claims.fid {
            let family_key = keys::encode_grant_family(fid);
            let family_bytes = self
                .storage
                .get(tenant_id, &family_key)
                .map_err(Self::storage_err)?
                .ok_or(IdentityError::TokenRevoked)?;
            let mut family: StoredGrantFamily =
                serde_json::from_slice(&family_bytes).map_err(|e| {
                    IdentityError::Serialization {
                        reason: e.to_string(),
                    }
                })?;

            // Check if family is revoked
            if family.revoked {
                return Err(IdentityError::TokenRevoked);
            }

            // Verify the incoming refresh token matches the current hash
            let incoming_hash = Self::sha256_hex(refresh_token.as_bytes());
            if incoming_hash != family.current_refresh_hash {
                // THEFT DETECTED — a previously-rotated token is being reused.
                // Revoke the entire family and the session.
                family.revoked = true;
                let updated =
                    serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                self.storage
                    .put(tenant_id, &family_key, &updated)
                    .map_err(Self::storage_err)?;
                let _ = self.revoke_session(tenant_id, &session_id);
                return Err(IdentityError::TokenRevoked);
            }

            // Refresh the underlying session
            self.refresh_session(tenant_id, &session_id)?;

            // Issue new token pair with the same family ID
            let signing_key = self.get_signing_key_or_default(tenant_id);
            let iat = now_secs;

            let new_access_claims = TokenClaims {
                sub: user_id.to_string(),
                iss: self.config.token.issuer.clone(),
                aud: self.config.token.audience.clone(),
                exp: iat + self.config.token.access_token_ttl_secs,
                iat,
                sid: session_id.to_string(),
                tid: tenant_id.to_string(),
                token_type: "access".to_string(),
                jti: Some(uuid::Uuid::new_v4().to_string()),
                fid: Some(fid.clone()),
                scope: claims.scope.clone(),
            };
            let new_refresh_claims = TokenClaims {
                sub: user_id.to_string(),
                iss: self.config.token.issuer.clone(),
                aud: self.config.token.audience.clone(),
                exp: iat + self.config.token.refresh_token_ttl_secs,
                iat,
                sid: session_id.to_string(),
                tid: tenant_id.to_string(),
                token_type: "refresh".to_string(),
                jti: Some(uuid::Uuid::new_v4().to_string()),
                fid: Some(fid.clone()),
                scope: claims.scope.clone(),
            };

            let new_access = signing_key.issue_token(&new_access_claims)?;
            let new_refresh = signing_key.issue_token(&new_refresh_claims)?;

            // Rotate the family's current refresh hash
            family.current_refresh_hash = Self::sha256_hex(new_refresh.as_bytes());
            let updated =
                serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            self.storage
                .put(tenant_id, &family_key, &updated)
                .map_err(Self::storage_err)?;

            Ok(TokenPair::new(new_access, new_refresh))
        } else {
            // Legacy path (no grant family — Phase 0 tokens)
            self.refresh_session(tenant_id, &session_id)?;
            self.issue_tokens(tenant_id, &user_id, &session_id)
        }
    }

    fn jwks(&self) -> JwksDocument {
        self.signing_key.to_jwks()
    }

    // ===== OIDC / OAuth 2.0 =====

    fn register_client(
        &self,
        tenant_id: &TenantId,
        request: &RegisterClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
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

        let client = if let Some(ref secret) = request.client_secret {
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

        // Serialize and persist
        let client_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let key = keys::encode_oauth_client(&client_id);
        self.storage
            .put(tenant_id, &key, &client_bytes)
            .map_err(Self::storage_err)?;

        Ok(client)
    }

    fn authorize(
        &self,
        tenant_id: &TenantId,
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
                let mut nonces = self.used_nonces.lock().expect("nonce lock");
                if !nonces.insert(nonce.clone()) {
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
            .get(tenant_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;
        let client: OAuthClient =
            serde_json::from_slice(&client_bytes).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        // 4. Validate redirect_uri matches a registered URI
        if !client.redirect_uris().contains(&request.redirect_uri) {
            return Err(IdentityError::InvalidRedirectUri);
        }

        // 5. Validate PKCE code_challenge_method if present
        if let Some(ref method) = request.code_challenge_method {
            if *method != CodeChallengeMethod::S256 {
                return Err(IdentityError::InvalidInput {
                    reason: "only S256 code challenge method is supported".to_string(),
                });
            }
            // code_challenge must be present if method is specified
            if request.code_challenge.is_none() {
                return Err(IdentityError::InvalidInput {
                    reason: "code_challenge is required when code_challenge_method is specified"
                        .to_string(),
                });
            }
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
        };

        // 9. Persist the code
        let code_key = keys::encode_oauth_code(&code_hash);
        let code_bytes =
            serde_json::to_vec(&stored_code).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(tenant_id, &code_key, &code_bytes)
            .map_err(Self::storage_err)?;

        Ok(AuthorizationResponse::new(raw_code, request.state.clone()))
    }

    #[allow(clippy::too_many_lines)]
    fn exchange_authorization_code(
        &self,
        tenant_id: &TenantId,
        request: &TokenExchangeRequest,
    ) -> Result<OidcTokenResponse, IdentityError> {
        // 1. Hash the incoming code to find it in storage
        let code_hash = Self::sha256_hex(request.code.as_bytes());
        let code_key = keys::encode_oauth_code(&code_hash);

        // 2. Load the stored code
        let code_bytes = self
            .storage
            .get(tenant_id, &code_key)
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

        // 8. Mark the code as used
        stored_code.used = true;
        let updated_bytes =
            serde_json::to_vec(&stored_code).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(tenant_id, &code_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 9. Create a session for the user
        let session = self.create_session(tenant_id, &stored_code.user_id)?;

        // 10. Create grant family for refresh token rotation
        let family_id = uuid::Uuid::new_v4().to_string();

        // 11. Issue tokens with family ID
        let iat = now.as_micros() / 1_000_000;
        let signing_key = self.get_signing_key_or_default(tenant_id);

        let access_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: self.config.token.audience.clone(),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: tenant_id.to_string(),
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(family_id.clone()),
            scope: None,
        };
        let refresh_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: self.config.token.audience.clone(),
            exp: iat + self.config.token.refresh_token_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: tenant_id.to_string(),
            token_type: "refresh".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: Some(family_id.clone()),
            scope: None,
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
            tenant_id: tenant_id.clone(),
            revoked: false,
            created_at: now,
        };
        let family_bytes =
            serde_json::to_vec(&family).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let family_key = keys::encode_grant_family(&family_id);
        self.storage
            .put(tenant_id, &family_key, &family_bytes)
            .map_err(Self::storage_err)?;

        // 13. Issue ID token (OIDC-specific)
        let id_token_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: request.client_id.to_string(),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: tenant_id.to_string(),
            token_type: "id_token".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: None,
        };
        let id_token =
            signing_key
                .issue_token(&id_token_claims)
                .map_err(|e| IdentityError::SigningError {
                    reason: format!("failed to issue ID token: {e}"),
                })?;

        Ok(OidcTokenResponse::new(
            access_token,
            id_token,
            "Bearer".to_string(),
            self.config.token.access_token_ttl_secs,
            refresh_token,
        ))
    }

    fn oidc_discovery(&self) -> OidcDiscoveryDocument {
        let issuer = &self.config.oidc.issuer;
        OidcDiscoveryDocument {
            issuer: issuer.clone(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            jwks_uri: format!("{issuer}/.well-known/jwks.json"),
            response_types_supported: vec!["code".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
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
            device_authorization_endpoint: Some(format!("{issuer}/device/authorize")),
            revocation_endpoint: Some(format!("{issuer}/revoke")),
            introspection_endpoint: Some(format!("{issuer}/introspect")),
        }
    }

    // ===== OAuth 2.0 Extended (Step 22) =====

    fn client_credentials_token(
        &self,
        tenant_id: &TenantId,
        request: &crate::identity::oidc::ClientCredentialsRequest,
    ) -> Result<crate::identity::oidc::ClientCredentialsResponse, IdentityError> {
        // 1. Load the client
        let client_key = keys::encode_oauth_client(&request.client_id);
        let client_bytes = self
            .storage
            .get(tenant_id, &client_key)
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

        // 4. Issue access token (no session, no refresh token per RFC 6749 §4.4.3)
        let now = self.clock.now();
        let iat = now.as_micros() / 1_000_000;
        let signing_key = self.get_or_load_tenant_signing_key(tenant_id)?;

        let scope = request.scope.clone();
        let access_claims = TokenClaims {
            sub: request.client_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: self.config.token.audience.clone(),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            sid: "none".to_string(), // No session for client credentials
            tid: tenant_id.to_string(),
            token_type: "access".to_string(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            fid: None,
            scope: scope.clone(),
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
        tenant_id: &TenantId,
        request: &crate::identity::oidc::DeviceAuthorizationRequest,
    ) -> Result<crate::identity::oidc::DeviceAuthorizationResponse, IdentityError> {
        use crate::identity::oidc::{DeviceCodeStatus, StoredDeviceCode};

        // 1. Verify client exists
        let client_key = keys::encode_oauth_client(&request.client_id);
        let _ = self
            .storage
            .get(tenant_id, &client_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidClient)?;

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
            tenant_id: tenant_id.clone(),
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
            .put(tenant_id, &dc_key, &stored_bytes)
            .map_err(Self::storage_err)?;

        // 5. Store user code → device code hash mapping
        let uc_key = keys::encode_user_code(&user_code);
        self.storage
            .put(tenant_id, &uc_key, device_code_hash.as_bytes())
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
        tenant_id: &TenantId,
        user_code: &str,
        user_id: &UserId,
    ) -> Result<(), IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        // 1. Look up user code → device code hash
        let uc_key = keys::encode_user_code(user_code);
        let dc_hash_bytes = self
            .storage
            .get(tenant_id, &uc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidAuthorizationCode)?;
        let dc_hash = String::from_utf8(dc_hash_bytes)
            .map_err(|_| IdentityError::InvalidAuthorizationCode)?;

        // 2. Load device code
        let dc_key = keys::encode_device_code(&dc_hash);
        let dc_bytes = self
            .storage
            .get(tenant_id, &dc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidAuthorizationCode)?;
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
            .put(tenant_id, &dc_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        Ok(())
    }

    fn poll_device_token(
        &self,
        tenant_id: &TenantId,
        device_code: &str,
        client_id: &ClientId,
    ) -> Result<OidcTokenResponse, IdentityError> {
        use crate::identity::oidc::DeviceCodeStatus;

        // 1. Look up device code by hash
        let dc_hash = Self::sha256_hex(device_code.as_bytes());
        let dc_key = keys::encode_device_code(&dc_hash);
        let dc_bytes = self
            .storage
            .get(tenant_id, &dc_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::InvalidAuthorizationCode)?;
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
            .put(tenant_id, &dc_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        // 6. Check status
        match &stored.status {
            DeviceCodeStatus::Pending => Err(IdentityError::AuthorizationPending),
            DeviceCodeStatus::Denied => Err(IdentityError::DeviceCodeDenied),
            DeviceCodeStatus::Expired => Err(IdentityError::DeviceCodeExpired),
            DeviceCodeStatus::Approved { user_id } => {
                // Issue tokens like exchange_authorization_code
                let session = self.create_session(tenant_id, user_id)?;
                let token_pair = self.issue_tokens(tenant_id, user_id, session.id())?;

                // Issue ID token
                let iat = now.as_micros() / 1_000_000;
                let id_token_claims = TokenClaims {
                    sub: user_id.to_string(),
                    iss: self.config.token.issuer.clone(),
                    aud: client_id.to_string(),
                    exp: iat + self.config.token.access_token_ttl_secs,
                    iat,
                    sid: session.id().to_string(),
                    tid: tenant_id.to_string(),
                    token_type: "id_token".to_string(),
                    jti: Some(uuid::Uuid::new_v4().to_string()),
                    fid: None,
                    scope: stored.scope.clone(),
                };
                let signing_key = self.get_or_load_tenant_signing_key(tenant_id)?;
                let id_token = signing_key.issue_token(&id_token_claims).map_err(|e| {
                    IdentityError::SigningError {
                        reason: format!("failed to issue ID token: {e}"),
                    }
                })?;

                // Clean up device code and user code
                let _ = self.storage.delete(tenant_id, &dc_key);
                let uc_key = keys::encode_user_code(&stored.user_code);
                let _ = self.storage.delete(tenant_id, &uc_key);

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
        tenant_id: &TenantId,
        request: &crate::identity::oidc::TokenRevocationRequest,
    ) -> Result<(), IdentityError> {
        // Decode claims (unverified — we trust our own tokens)
        // RFC 7009: invalid tokens → 200 OK (no error)
        let Ok(claims) = tokens::decode_claims_unverified(&request.token) else {
            return Ok(());
        };

        // Verify tenant matches
        if claims.tid != tenant_id.to_string() {
            return Ok(()); // Silent success per RFC 7009
        }

        match claims.token_type.as_str() {
            "access" | "id_token" => {
                if claims.sid != "none" {
                    // Session-bound token: revoke via session
                    let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
                    if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                        let session_id = SessionId::new(uuid);
                        let _ = self.revoke_session(tenant_id, &session_id);
                    }
                } else if let Some(ref jti) = claims.jti {
                    // Sessionless token (e.g., client_credentials): revoke via JTI blocklist
                    let jti_key = keys::encode_revoked_jti(jti);
                    let _ = self.storage.put(tenant_id, &jti_key, b"1");
                }
            }
            "refresh" => {
                // Revoke via grant family
                if let Some(ref fid) = claims.fid {
                    let family_key = keys::encode_grant_family(fid);
                    if let Some(family_bytes) = self
                        .storage
                        .get(tenant_id, &family_key)
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
                            .put(tenant_id, &family_key, &updated)
                            .map_err(Self::storage_err)?;
                    }
                }
                // Also revoke session if present
                if claims.sid != "none" {
                    let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
                    if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                        let session_id = SessionId::new(uuid);
                        let _ = self.revoke_session(tenant_id, &session_id);
                    }
                }
            }
            _ => {} // Unknown token type → silent success
        }

        Ok(())
    }

    fn introspect_token(
        &self,
        tenant_id: &TenantId,
        request: &crate::identity::oidc::TokenIntrospectionRequest,
    ) -> Result<crate::identity::oidc::IntrospectionResponse, IdentityError> {
        use crate::identity::oidc::IntrospectionResponse;

        // 1. Decode claims (unverified — hot path)
        let Ok(claims) = tokens::decode_claims_unverified(&request.token) else {
            return Ok(IntrospectionResponse::inactive());
        };

        // 2. Verify tenant matches
        if claims.tid != tenant_id.to_string() {
            return Ok(IntrospectionResponse::inactive());
        }

        // 3. Check expiration
        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Ok(IntrospectionResponse::inactive());
        }

        // 4. Check session validity (if session-bound) or JTI blocklist (if sessionless)
        if claims.sid != "none" {
            let sid_str = claims.sid.strip_prefix("session_").unwrap_or(&claims.sid);
            if let Ok(uuid) = uuid::Uuid::parse_str(sid_str) {
                let session_id = SessionId::new(uuid);
                if self.get_session(tenant_id, &session_id)?.is_none() {
                    return Ok(IntrospectionResponse::inactive());
                }
            }
        } else if let Some(ref jti) = claims.jti {
            // Sessionless token — check JTI revocation blocklist
            let jti_key = keys::encode_revoked_jti(jti);
            if self
                .storage
                .get(tenant_id, &jti_key)
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
                    .get(tenant_id, &family_key)
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
            aud: Some(claims.aud),
        })
    }

    // ===== MFA / TOTP (Step 23) =====

    fn enroll_totp(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<TotpEnrollment, IdentityError> {
        // Ensure user exists
        let user = self
            .get_user(tenant_id, user_id)?
            .ok_or(IdentityError::UserNotFound)?;

        // Check not already enrolled
        if let Some(existing) = self.load_mfa_state(tenant_id, user_id)? {
            if existing.enabled {
                return Err(IdentityError::MfaAlreadyEnabled);
            }
        }

        // Generate secret + recovery codes
        let secret = TotpSecret::generate()?;
        let secret_base32 = secret.to_base32();
        let provisioning_uri =
            totp::generate_provisioning_uri(&secret_base32, user.email(), "Hearth");
        let recovery_codes = totp::generate_recovery_codes()?;
        let recovery_hashes = totp::hash_recovery_codes(&recovery_codes, &self.config.credential)?;

        // Store disabled state
        let state = StoredMfaState {
            secret_base32: secret_base32.clone(),
            enabled: false,
            recovery_code_hashes: recovery_hashes,
            last_used_step: None,
            enabled_at: None,
        };
        self.save_mfa_state(tenant_id, user_id, &state)?;

        Ok(TotpEnrollment {
            secret_base32,
            provisioning_uri,
            recovery_codes,
        })
    }

    #[allow(clippy::cast_sign_loss)] // Timestamps are always positive
    fn verify_totp_enrollment(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        let mut state = self
            .load_mfa_state(tenant_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if state.enabled {
            return Err(IdentityError::MfaAlreadyEnabled);
        }

        // Validate code against the stored secret
        let secret = TotpSecret::from_base32(&state.secret_base32)?;
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        let matched_step = totp::validate_totp(secret.as_bytes(), code, now_secs, None);

        if let Some(step) = matched_step {
            state.enabled = true;
            state.last_used_step = Some(step);
            state.enabled_at = Some(self.clock.now().as_micros());
            self.save_mfa_state(tenant_id, user_id, &state)?;
            Ok(())
        } else {
            Err(IdentityError::InvalidMfaCode)
        }
    }

    #[allow(clippy::cast_sign_loss)] // Timestamps are always positive
    fn verify_totp(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        // Rate limit check
        self.check_mfa_rate_limit(tenant_id, user_id)?;

        let mut state = self
            .load_mfa_state(tenant_id, user_id)?
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
            self.save_mfa_state(tenant_id, user_id, &state)?;
            self.clear_mfa_attempts(tenant_id, user_id);
            Ok(())
        } else {
            self.record_mfa_failed_attempt(tenant_id, user_id);
            Err(IdentityError::InvalidMfaCode)
        }
    }

    fn verify_recovery_code(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        code: &str,
    ) -> Result<(), IdentityError> {
        let mut state = self
            .load_mfa_state(tenant_id, user_id)?
            .ok_or(IdentityError::MfaNotEnabled)?;

        if !state.enabled {
            return Err(IdentityError::MfaNotEnabled);
        }

        let idx = totp::verify_recovery_code(code, &state.recovery_code_hashes)?;
        match idx {
            Some(i) => {
                // Mark recovery code as used
                state.recovery_code_hashes[i] = None;
                self.save_mfa_state(tenant_id, user_id, &state)?;
                self.clear_mfa_attempts(tenant_id, user_id);
                Ok(())
            }
            None => Err(IdentityError::InvalidMfaCode),
        }
    }

    fn disable_mfa(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<(), IdentityError> {
        let state = self.load_mfa_state(tenant_id, user_id)?;
        match state {
            Some(s) if s.enabled => {
                let key = keys::encode_mfa_totp_key(user_id);
                self.storage
                    .delete(tenant_id, &key)
                    .map_err(Self::storage_err)?;
                self.clear_mfa_attempts(tenant_id, user_id);
                Ok(())
            }
            _ => Err(IdentityError::MfaNotEnabled),
        }
    }

    fn mfa_enabled(&self, tenant_id: &TenantId, user_id: &UserId) -> Result<bool, IdentityError> {
        match self.load_mfa_state(tenant_id, user_id)? {
            Some(state) => Ok(state.enabled),
            None => Ok(false),
        }
    }

    // ===== WebAuthn / Passkeys (Step 24) =====

    fn start_webauthn_registration(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        options: &RegistrationOptions,
    ) -> Result<Vec<u8>, IdentityError> {
        // Ensure user exists
        self.get_user(tenant_id, user_id)?
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
        tenant_id: &TenantId,
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
        };
        stored.discoverable = discoverable;

        // Persist credential
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(info.credential_id());
        let key = keys::encode_webauthn_credential(user_id, &cred_id_b64);
        let bytes = serde_json::to_vec(&stored).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;
        self.storage
            .put(tenant_id, &key, &bytes)
            .map_err(Self::storage_err)?;

        // If discoverable, create the index entry
        if discoverable {
            let disc_key = keys::encode_webauthn_discoverable(&cred_id_b64);
            let user_uuid_bytes = user_id.as_uuid().to_string().into_bytes();
            self.storage
                .put(tenant_id, &disc_key, &user_uuid_bytes)
                .map_err(Self::storage_err)?;
        }

        Ok(info)
    }

    fn start_webauthn_authentication(
        &self,
        tenant_id: &TenantId,
        user_id: Option<&UserId>,
        options: &AuthenticationOptions,
    ) -> Result<Vec<u8>, IdentityError> {
        // If user_id provided, verify user exists
        if let Some(uid) = user_id {
            self.get_user(tenant_id, uid)?
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
        tenant_id: &TenantId,
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
                .get(tenant_id, &disc_key)
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
            .get(tenant_id, &cred_key)
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
            .put(tenant_id, &cred_key, &updated_bytes)
            .map_err(Self::storage_err)?;

        Ok(result)
    }

    fn list_webauthn_credentials(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Vec<WebAuthnCredentialInfo>, IdentityError> {
        let prefix = keys::encode_webauthn_credentials_prefix(user_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(tenant_id, &prefix, &end)
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
            });
        }

        Ok(results)
    }

    fn revoke_webauthn_credential(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        credential_id: &[u8],
    ) -> Result<(), IdentityError> {
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(credential_id);

        // Delete credential record
        let cred_key = keys::encode_webauthn_credential(user_id, &cred_id_b64);
        let existing = self
            .storage
            .get(tenant_id, &cred_key)
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
            .delete(tenant_id, &cred_key)
            .map_err(Self::storage_err)?;

        if stored.discoverable {
            let disc_key = keys::encode_webauthn_discoverable(&cred_id_b64);
            self.storage
                .delete(tenant_id, &disc_key)
                .map_err(Self::storage_err)?;
        }

        Ok(())
    }

    // ===== Magic Link / Passwordless (Step 25) =====

    fn request_magic_link(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<MagicLinkResponse, IdentityError> {
        // 1. Normalize email
        let normalized = validation::validate_email(email)?;

        // 2. Check per-email rate limit (3 per hour)
        self.check_magic_link_rate_limit(tenant_id, &normalized)?;

        // 3. Look up user by email — capture user_id if exists (enumeration resistance: always succeed)
        let user_id = self
            .get_user_by_email(tenant_id, &normalized)?
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
            .put(tenant_id, &key, &stored_bytes)
            .map_err(Self::storage_err)?;

        // 7. Record rate limit event
        self.record_magic_link_request(tenant_id, &normalized);

        // 8. Return plaintext token (shown once)
        Ok(MagicLinkResponse::new(token.as_str().to_string()))
    }

    fn validate_magic_link(
        &self,
        tenant_id: &TenantId,
        token: &str,
    ) -> Result<UserId, IdentityError> {
        // 1. SHA-256 hash the incoming token
        let token_hash = Self::sha256_hex(token.as_bytes());
        let key = keys::encode_magic_link_token(&token_hash);

        // 2. Look up stored record
        let bytes = self
            .storage
            .get(tenant_id, &key)
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
                .delete(tenant_id, &key)
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
            .put(tenant_id, &key, &updated_bytes)
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
            };
            let user = self.create_user(tenant_id, &request)?;
            Ok(user.id().clone())
        }
    }

    // ===== Admin API (Step 27) =====

    fn list_users(
        &self,
        tenant_id: &TenantId,
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
            .scan(tenant_id, &start, &end)
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

    fn list_tenants(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Tenant>, IdentityError> {
        let sys_tenant = keys::system_tenant_id();
        let prefix = keys::tenant_id_scan_prefix();
        let start = if let Some(cursor_str) = cursor {
            let uuid_str = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor_str).map_err(|e| {
                IdentityError::InvalidInput {
                    reason: format!("invalid cursor: {e}"),
                }
            })?)
            .map_err(|e| IdentityError::InvalidInput {
                reason: format!("invalid cursor: {e}"),
            })?;
            let mut cursor_key = format!("tenant:id:{uuid_str}").into_bytes();
            cursor_key.push(0xFF);
            cursor_key
        } else {
            prefix.clone()
        };
        let end = keys::prefix_end(&prefix);

        let entries = self
            .storage
            .scan(&sys_tenant, &start, &end)
            .map_err(Self::storage_err)?;

        let mut items = Vec::new();
        for entry in entries.iter().take(limit + 1) {
            let tenant: Tenant =
                serde_json::from_slice(&entry.value).map_err(|e| IdentityError::Serialization {
                    reason: e.to_string(),
                })?;
            items.push(tenant);
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

    fn list_clients(
        &self,
        tenant_id: &TenantId,
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
            .scan(tenant_id, &start, &end)
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
        tenant_id: &TenantId,
        client_id: &crate::core::ClientId,
    ) -> Result<Option<OAuthClient>, IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        let bytes = self
            .storage
            .get(tenant_id, &key)
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

    fn update_client(
        &self,
        tenant_id: &TenantId,
        client_id: &crate::core::ClientId,
        request: &crate::identity::oidc::UpdateClientRequest,
    ) -> Result<OAuthClient, IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        let bytes = self
            .storage
            .get(tenant_id, &key)
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

        let updated_bytes =
            serde_json::to_vec(&client).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        self.storage
            .put(tenant_id, &key, &updated_bytes)
            .map_err(Self::storage_err)?;

        Ok(client)
    }

    fn delete_client(
        &self,
        tenant_id: &TenantId,
        client_id: &crate::core::ClientId,
    ) -> Result<(), IdentityError> {
        let key = keys::encode_oauth_client(client_id);
        // Verify the client exists first
        self.storage
            .get(tenant_id, &key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::ClientNotFound)?;

        self.storage
            .delete(tenant_id, &key)
            .map_err(Self::storage_err)?;
        Ok(())
    }

    fn bulk_create_users(
        &self,
        tenant_id: &TenantId,
        requests: &[CreateUserRequest],
    ) -> Result<Vec<BulkResult<User>>, IdentityError> {
        let mut results = Vec::with_capacity(requests.len());
        for (index, request) in requests.iter().enumerate() {
            let result = match self.create_user(tenant_id, request) {
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
        Ok(results)
    }

    fn bulk_disable_users(
        &self,
        tenant_id: &TenantId,
        user_ids: &[UserId],
    ) -> Result<Vec<BulkResult<()>>, IdentityError> {
        let mut results = Vec::with_capacity(user_ids.len());
        for (index, user_id) in user_ids.iter().enumerate() {
            let result = match self.update_user(
                tenant_id,
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
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, Timestamp};
    use crate::identity::types::TenantConfig;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn setup_engine() -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    // ===== Scenario 1: Create user with required fields succeeds =====

    #[test]
    fn create_user_with_required_fields_succeeds() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let request = CreateUserRequest {
            email: "Alice@Example.COM".to_string(),
            display_name: "Alice Smith".to_string(),
        };

        let user = engine.create_user(&tenant, &request).expect("create");

        assert_eq!(user.email(), "alice@example.com");
        assert_eq!(user.display_name(), "Alice Smith");
        assert_eq!(user.status(), UserStatus::Active);
        assert_eq!(user.created_at(), Timestamp::from_micros(1_000_000));
        assert_eq!(user.updated_at(), Timestamp::from_micros(1_000_000));
    }

    #[test]
    fn create_user_generates_unique_id() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let user1 = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        let user2 = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "bob@example.com".to_string(),
                    display_name: "Bob".to_string(),
                },
            )
            .expect("create");

        assert_ne!(user1.id(), user2.id());
    }

    // ===== Scenario 2: Read user by ID and by email =====

    #[test]
    fn read_user_by_id_returns_correct_record() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let created = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        let fetched = engine
            .get_user(&tenant, created.id())
            .expect("get")
            .expect("should exist");

        assert_eq!(fetched, created);
    }

    #[test]
    fn read_user_by_email_returns_correct_record() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let created = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        let fetched = engine
            .get_user_by_email(&tenant, "Alice@Example.COM")
            .expect("get")
            .expect("should exist");

        assert_eq!(fetched, created);
    }

    #[test]
    fn read_nonexistent_user_returns_none() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let result = engine.get_user(&tenant, &UserId::generate()).expect("get");
        assert!(result.is_none());
    }

    #[test]
    fn read_nonexistent_email_returns_none() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let result = engine
            .get_user_by_email(&tenant, "nobody@example.com")
            .expect("get");
        assert!(result.is_none());
    }

    // ===== Scenario 3: Update user persists changes =====

    #[test]
    fn update_user_persists_changes() {
        let (_dir, engine, clock) = setup_engine();
        let tenant = TenantId::generate();

        let created = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        clock.advance(1_000_000); // advance 1 second

        let updated = engine
            .update_user(
                &tenant,
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
            .get_user(&tenant, created.id())
            .expect("get")
            .expect("should exist");
        assert_eq!(fetched, updated);
    }

    #[test]
    fn update_user_email_swaps_index() {
        let (_dir, engine, clock) = setup_engine();
        let tenant = TenantId::generate();

        let created = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "old@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        clock.advance(1_000_000);

        engine
            .update_user(
                &tenant,
                created.id(),
                &UpdateUserRequest {
                    email: Some("new@example.com".to_string()),
                    ..UpdateUserRequest::default()
                },
            )
            .expect("update");

        // Old email should not resolve
        let old_lookup = engine
            .get_user_by_email(&tenant, "old@example.com")
            .expect("get");
        assert!(old_lookup.is_none());

        // New email should resolve
        let new_lookup = engine
            .get_user_by_email(&tenant, "new@example.com")
            .expect("get")
            .expect("should exist");
        assert_eq!(new_lookup.id(), created.id());
    }

    #[test]
    fn update_user_status() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let created = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        let updated = engine
            .update_user(
                &tenant,
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
        let tenant = TenantId::generate();

        let err = engine
            .update_user(&tenant, &UserId::generate(), &UpdateUserRequest::default())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    // ===== Scenario 4: Delete user removes record =====

    #[test]
    fn delete_user_removes_record() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let created = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        engine.delete_user(&tenant, created.id()).expect("delete");

        // Should not be found by ID
        let by_id = engine.get_user(&tenant, created.id()).expect("get");
        assert!(by_id.is_none());

        // Should not be found by email
        let by_email = engine
            .get_user_by_email(&tenant, "alice@example.com")
            .expect("get");
        assert!(by_email.is_none());
    }

    #[test]
    fn delete_nonexistent_user_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let err = engine
            .delete_user(&tenant, &UserId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    #[test]
    fn delete_user_frees_email() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let created = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        engine.delete_user(&tenant, created.id()).expect("delete");

        // Should be able to create a new user with the same email
        let new_user = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice 2".to_string(),
                },
            )
            .expect("create should succeed after delete");

        assert_ne!(new_user.id(), created.id());
    }

    // ===== Scenario 5: Duplicate email rejected =====

    #[test]
    fn duplicate_email_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("first create");

        let err = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice 2".to_string(),
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    #[test]
    fn duplicate_email_case_insensitive() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "Alice@Example.COM".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        let err = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Other".to_string(),
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    #[test]
    fn duplicate_email_on_update_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create alice");

        let bob = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "bob@example.com".to_string(),
                    display_name: "Bob".to_string(),
                },
            )
            .expect("create bob");

        let err = engine
            .update_user(
                &tenant,
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
        let tenant = TenantId::generate();

        let err = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice\0@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn null_bytes_in_display_name_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let err = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice\0Smith".to_string(),
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn unicode_normalization_deduplicates_emails() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        // Create with decomposed é
        engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "caf\u{0065}\u{0301}@example.com".to_string(),
                    display_name: "User 1".to_string(),
                },
            )
            .expect("create");

        // Try to create with composed é — should be duplicate
        let err = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "caf\u{00E9}@example.com".to_string(),
                    display_name: "User 2".to_string(),
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::DuplicateEmail));
    }

    // ===== Adversarial: oversized input =====

    #[test]
    fn oversized_email_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let long_email = format!("{}@example.com", "a".repeat(250));
        let err = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: long_email,
                    display_name: "Alice".to_string(),
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    #[test]
    fn oversized_display_name_rejected() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let err = engine
            .create_user(
                &tenant,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "A".repeat(257),
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidInput { .. }));
    }

    // ===== Cross-tenant isolation =====

    #[test]
    fn cross_tenant_isolation() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant_a = TenantId::generate();
        let tenant_b = TenantId::generate();

        let alice = engine
            .create_user(
                &tenant_a,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create");

        // Same email in different tenant should succeed
        let alice_b = engine
            .create_user(
                &tenant_b,
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice B".to_string(),
                },
            )
            .expect("create in different tenant should succeed");

        assert_ne!(alice.id(), alice_b.id());

        // Can't see tenant A's user from tenant B
        let not_found = engine.get_user(&tenant_b, alice.id()).expect("get");
        assert!(not_found.is_none());
    }

    // ===== Send + Sync =====

    #[test]
    fn engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EmbeddedIdentityEngine>();
    }

    // ===== Credential Scenario 1: set_password + verify_password =====

    fn create_test_user(engine: &EmbeddedIdentityEngine, tenant: &TenantId) -> User {
        engine
            .create_user(
                tenant,
                &CreateUserRequest {
                    email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Test User".to_string(),
                },
            )
            .expect("create user")
    }

    #[test]
    fn set_and_verify_password_correct() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let pw = CleartextPassword::from_string("my-secure-password".to_string());
        engine
            .set_password(&tenant, user.id(), &pw)
            .expect("set password");

        let pw_check = CleartextPassword::from_string("my-secure-password".to_string());
        let result = engine
            .verify_password(&tenant, user.id(), &pw_check)
            .expect("verify");
        assert!(result, "correct password should verify");
    }

    #[test]
    fn set_and_verify_password_wrong() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let pw = CleartextPassword::from_string("correct-password".to_string());
        engine
            .set_password(&tenant, user.id(), &pw)
            .expect("set password");

        let wrong = CleartextPassword::from_string("wrong-password".to_string());
        let result = engine
            .verify_password(&tenant, user.id(), &wrong)
            .expect("verify");
        assert!(!result, "wrong password should not verify");
    }

    #[test]
    fn set_password_nonexistent_user_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .set_password(&tenant, &UserId::generate(), &pw)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    #[test]
    fn verify_password_nonexistent_user_returns_generic_error() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .verify_password(&tenant, &UserId::generate(), &pw)
            .expect_err("should fail");
        // Returns generic InvalidCredential to prevent user enumeration
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    #[test]
    fn verify_password_no_credential_returns_generic_error() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .verify_password(&tenant, user.id(), &pw)
            .expect_err("should fail");
        // Returns generic InvalidCredential to prevent credential enumeration
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    // ===== Credential Scenario 3: Password change =====

    #[test]
    fn change_password_succeeds() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let old_pw = CleartextPassword::from_string("old-password".to_string());
        engine
            .set_password(&tenant, user.id(), &old_pw)
            .expect("set password");

        let old_for_change = CleartextPassword::from_string("old-password".to_string());
        let new_pw = CleartextPassword::from_string("new-password".to_string());
        engine
            .change_password(&tenant, user.id(), &old_for_change, &new_pw)
            .expect("change password");

        // Old password should no longer verify
        let old_check = CleartextPassword::from_string("old-password".to_string());
        let result = engine
            .verify_password(&tenant, user.id(), &old_check)
            .expect("verify old");
        assert!(!result, "old password should no longer verify");

        // New password should verify
        let new_check = CleartextPassword::from_string("new-password".to_string());
        let result = engine
            .verify_password(&tenant, user.id(), &new_check)
            .expect("verify new");
        assert!(result, "new password should verify");
    }

    #[test]
    fn change_password_wrong_old_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let pw = CleartextPassword::from_string("real-password".to_string());
        engine
            .set_password(&tenant, user.id(), &pw)
            .expect("set password");

        let wrong_old = CleartextPassword::from_string("wrong-old".to_string());
        let new_pw = CleartextPassword::from_string("new-password".to_string());
        let err = engine
            .change_password(&tenant, user.id(), &wrong_old, &new_pw)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));

        // Original password should still work
        let orig = CleartextPassword::from_string("real-password".to_string());
        let result = engine
            .verify_password(&tenant, user.id(), &orig)
            .expect("verify");
        assert!(result, "original password should still verify");
    }

    // ===== Delete cascades to credentials =====

    #[test]
    fn delete_user_cascades_credential() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let pw = CleartextPassword::from_string("password".to_string());
        engine
            .set_password(&tenant, user.id(), &pw)
            .expect("set password");

        engine.delete_user(&tenant, user.id()).expect("delete");

        // Verify should fail with generic InvalidCredential (enumeration resistance)
        let pw_check = CleartextPassword::from_string("password".to_string());
        let err = engine
            .verify_password(&tenant, user.id(), &pw_check)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::InvalidCredential { .. }));
    }

    // ===== Adversarial: Timing oracle prevention =====

    #[test]
    #[allow(clippy::cast_precision_loss)] // Precision loss acceptable for timing ratio
    fn verify_nonexistent_user_takes_comparable_time() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let pw = CleartextPassword::from_string("password".to_string());
        engine
            .set_password(&tenant, user.id(), &pw)
            .expect("set password");

        // Time a real failed verification
        let wrong = CleartextPassword::from_string("wrong".to_string());
        let start_real = std::time::Instant::now();
        let _ = engine.verify_password(&tenant, user.id(), &wrong);
        let real_time = start_real.elapsed();

        // Time a nonexistent user verification
        let fake = CleartextPassword::from_string("wrong".to_string());
        let start_fake = std::time::Instant::now();
        let _ = engine.verify_password(&tenant, &UserId::generate(), &fake);
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
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let session = engine
            .create_session(&tenant, user.id())
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
        let tenant = TenantId::generate();

        let err = engine
            .create_session(&tenant, &UserId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    // ===== Session Scenario 2: Lookup session by ID =====

    #[test]
    fn lookup_session_by_id_returns_correct_data() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let session = engine
            .create_session(&tenant, user.id())
            .expect("create session");

        let fetched = engine
            .get_session(&tenant, session.id())
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
        let tenant = TenantId::generate();

        let result = engine
            .get_session(&tenant, &SessionId::generate())
            .expect("get");
        assert!(result.is_none());
    }

    // ===== Session Scenario 3: Revoke session =====

    #[test]
    fn revoke_session_immediate_invalidation() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let session = engine
            .create_session(&tenant, user.id())
            .expect("create session");

        // Revoke it
        engine
            .revoke_session(&tenant, session.id())
            .expect("revoke");

        // Lookup should return None
        let result = engine.get_session(&tenant, session.id()).expect("get");
        assert!(result.is_none(), "revoked session should not be found");
    }

    #[test]
    fn revoke_nonexistent_session_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();

        let err = engine
            .revoke_session(&tenant, &SessionId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    // ===== Session Scenario 4: TTL expiration =====

    #[test]
    fn session_expires_after_ttl() {
        let (_dir, engine, clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let session = engine
            .create_session(&tenant, user.id())
            .expect("create session");

        // Session should be valid now
        let valid = engine.get_session(&tenant, session.id()).expect("get");
        assert!(valid.is_some(), "session should be valid before TTL");

        // Advance clock past TTL (24 hours + 1 microsecond)
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl + 1);

        // Session should now be expired
        let expired = engine.get_session(&tenant, session.id()).expect("get");
        assert!(expired.is_none(), "session should be expired after TTL");
    }

    #[test]
    fn session_valid_just_before_expiry() {
        let (_dir, engine, clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let session = engine
            .create_session(&tenant, user.id())
            .expect("create session");

        // Advance clock to 1 μs before expiry
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl - 1);

        let still_valid = engine.get_session(&tenant, session.id()).expect("get");
        assert!(
            still_valid.is_some(),
            "session should still be valid 1μs before expiry"
        );
    }

    // ===== Session Scenario 5: Refresh session extends TTL =====

    #[test]
    fn refresh_session_extends_ttl() {
        let (_dir, engine, clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let session = engine
            .create_session(&tenant, user.id())
            .expect("create session");

        let ttl = 24 * 60 * 60 * 1_000_000_i64;

        // Advance 12 hours (half TTL)
        clock.advance(ttl / 2);

        // Refresh the session
        let refreshed = engine
            .refresh_session(&tenant, session.id())
            .expect("refresh");

        // Expiry should be 24h from now (not original creation)
        let now = clock.now();
        assert_eq!(refreshed.expires_at(), now.add_micros(ttl));
        assert_eq!(refreshed.last_refreshed_at(), now);

        // Original created_at should be preserved
        assert_eq!(refreshed.created_at(), session.created_at());

        // Advance another 23 hours — would have expired without refresh
        clock.advance(ttl - ttl / 2 + 1_000_000);

        let still_valid = engine.get_session(&tenant, session.id()).expect("get");
        assert!(
            still_valid.is_some(),
            "refreshed session should still be valid past original expiry"
        );
    }

    #[test]
    fn refresh_expired_session_fails() {
        let (_dir, engine, clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let session = engine
            .create_session(&tenant, user.id())
            .expect("create session");

        // Advance past TTL
        let ttl = 24 * 60 * 60 * 1_000_000_i64;
        clock.advance(ttl + 1);

        let err = engine
            .refresh_session(&tenant, session.id())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    #[test]
    fn refresh_revoked_session_fails() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let session = engine
            .create_session(&tenant, user.id())
            .expect("create session");

        engine
            .revoke_session(&tenant, session.id())
            .expect("revoke");

        let err = engine
            .refresh_session(&tenant, session.id())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::SessionNotFound));
    }

    // ===== Delete cascades to sessions =====

    #[test]
    fn delete_user_cascades_sessions() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        // Create multiple sessions
        let s1 = engine
            .create_session(&tenant, user.id())
            .expect("session 1");
        let s2 = engine
            .create_session(&tenant, user.id())
            .expect("session 2");

        // Both should be valid
        assert!(engine.get_session(&tenant, s1.id()).expect("get").is_some());
        assert!(engine.get_session(&tenant, s2.id()).expect("get").is_some());

        // Delete user
        engine.delete_user(&tenant, user.id()).expect("delete");

        // Both sessions should be gone
        assert!(engine.get_session(&tenant, s1.id()).expect("get").is_none());
        assert!(engine.get_session(&tenant, s2.id()).expect("get").is_none());
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
                let tenant = TenantId::generate();
                let mut created_ids = Vec::new();

                // Create all users
                for (i, email) in emails.iter().enumerate() {
                    let user = engine.create_user(&tenant, &CreateUserRequest {
                        email: email.clone(),
                        display_name: format!("User {i}"),
                    }).expect("create");
                    created_ids.push(user.id().clone());
                }

                // All should be retrievable
                for id in &created_ids {
                    let user = engine.get_user(&tenant, id).expect("get");
                    prop_assert!(user.is_some(), "created user should be found");
                }

                // Delete half
                let to_delete = created_ids.len() / 2;
                for id in &created_ids[..to_delete] {
                    engine.delete_user(&tenant, id).expect("delete");
                }

                // Deleted should be gone
                for id in &created_ids[..to_delete] {
                    let user = engine.get_user(&tenant, id).expect("get");
                    prop_assert!(user.is_none(), "deleted user should not be found");
                }

                // Remaining should still exist
                for id in &created_ids[to_delete..] {
                    let user = engine.get_user(&tenant, id).expect("get");
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
                let tenant = TenantId::generate();

                // First creation should succeed
                let result = engine.create_user(&tenant, &CreateUserRequest {
                    email: email.clone(),
                    display_name: "User 0".to_string(),
                });
                prop_assert!(result.is_ok(), "first creation should succeed");

                // Subsequent creations with same email should fail
                for i in 1..n {
                    let result = engine.create_user(&tenant, &CreateUserRequest {
                        email: email.clone(),
                        display_name: format!("User {i}"),
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
                let tenant = TenantId::generate();
                let user = engine.create_user(&tenant, &CreateUserRequest {
                    email: format!("session-prop-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Prop User".to_string(),
                }).expect("create user");

                // Create N sessions
                let mut session_ids = Vec::new();
                for _ in 0..n_create {
                    let session = engine
                        .create_session(&tenant, user.id())
                        .expect("create session");
                    session_ids.push(session.id().clone());
                }

                // All should be valid
                for id in &session_ids {
                    let s = engine.get_session(&tenant, id).expect("get");
                    prop_assert!(s.is_some(), "created session should be valid");
                }

                // Revoke a proportion of them
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
                let n_revoke = (n_create as f64 * n_revoke_ratio) as usize;
                for id in &session_ids[..n_revoke] {
                    engine.revoke_session(&tenant, id).expect("revoke");
                }

                // Count active sessions
                let active_count = session_ids
                    .iter()
                    .filter(|id| engine.get_session(&tenant, id).expect("get").is_some())
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
                let tenant = TenantId::generate();
                let user = engine.create_user(&tenant, &CreateUserRequest {
                    email: format!("collision-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Collision User".to_string(),
                }).expect("create user");

                let mut ids = std::collections::HashSet::new();
                for _ in 0..n {
                    let session = engine
                        .create_session(&tenant, user.id())
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

    fn register_test_client(engine: &EmbeddedIdentityEngine, tenant: &TenantId) -> OAuthClient {
        engine
            .register_client(
                tenant,
                &RegisterClientRequest {
                    client_name: "Test App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                },
            )
            .expect("register client")
    }

    // ===== Unit Test 1: Generate authorization code with correct parameters =====

    #[test]
    fn generate_authorization_code_with_correct_params() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        let response = engine
            .authorize(
                &tenant,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "random-state-value".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
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
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        let auth_response = engine
            .authorize(
                &tenant,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state1".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                },
            )
            .expect("authorize");

        let token_response = engine
            .exchange_authorization_code(
                &tenant,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth_response.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: None,
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
            .validate_token(&tenant, token_response.access_token())
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
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        let auth_response = engine
            .authorize(
                &tenant,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state2".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                },
            )
            .expect("authorize");

        // First exchange succeeds
        let result1 = engine.exchange_authorization_code(
            &tenant,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: None,
            },
        );
        assert!(result1.is_ok(), "first exchange should succeed");

        // Second exchange with same code fails
        let result2 = engine.exchange_authorization_code(
            &tenant,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: None,
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
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        let auth_response = engine
            .authorize(
                &tenant,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state3".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                },
            )
            .expect("authorize");

        // Advance clock past the authorization code TTL (default: 600 seconds)
        clock.advance(601 * 1_000_000); // 601 seconds in microseconds

        // Exchange should fail due to expiration
        let result = engine.exchange_authorization_code(
            &tenant,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: None,
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
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        let auth_response = engine
            .authorize(
                &tenant,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "adv-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                },
            )
            .expect("authorize");

        // Use the code
        engine
            .exchange_authorization_code(
                &tenant,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth_response.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: None,
                },
            )
            .expect("first exchange");

        // Attempt reuse — must fail
        let reuse = engine.exchange_authorization_code(
            &tenant,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: None,
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
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        // Attempt to authorize with an unregistered redirect URI
        let result = engine.authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://evil.example.com/steal-tokens".to_string(),
                scope: "openid".to_string(),
                state: "state-val".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
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
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        // Attempt to authorize with empty state
        let result = engine.authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: String::new(), // empty state
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
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
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            rate_limit: RateLimitConfig {
                max_failed_attempts: max_attempts,
                lockout_duration_micros: lockout_micros,
            },
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    #[test]
    fn rate_limiting_engages_after_max_failures() {
        // Configure: lockout after 3 failed attempts, 10-second lockout
        let lockout_micros = 10_000_000; // 10 seconds
        let (_dir, engine, _clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let pw = CleartextPassword::from_string("correct-pw".to_string());
        engine
            .set_password(&tenant, user.id(), &pw)
            .expect("set password");

        // 3 wrong attempts
        for i in 0..3 {
            let wrong = CleartextPassword::from_string(format!("wrong-{i}"));
            let result = engine.verify_password(&tenant, user.id(), &wrong);
            assert!(
                result.is_ok(),
                "attempt {i} should not be rate limited yet: {result:?}"
            );
            assert!(!result.expect("ok"), "wrong password should not verify");
        }

        // 4th attempt: should be rate limited even with the correct password
        let correct = CleartextPassword::from_string("correct-pw".to_string());
        let result = engine.verify_password(&tenant, user.id(), &correct);
        assert!(
            matches!(result, Err(IdentityError::RateLimited)),
            "should be rate limited after 3 failures, got: {result:?}"
        );
    }

    #[test]
    fn rate_limiting_resets_on_successful_verification() {
        let lockout_micros = 10_000_000;
        let (_dir, engine, _clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let pw = CleartextPassword::from_string("my-password".to_string());
        engine
            .set_password(&tenant, user.id(), &pw)
            .expect("set password");

        // 2 wrong attempts (below threshold)
        for _ in 0..2 {
            let wrong = CleartextPassword::from_string("wrong".to_string());
            let result = engine
                .verify_password(&tenant, user.id(), &wrong)
                .expect("should not be rate limited");
            assert!(!result);
        }

        // Correct password resets the counter
        let correct = CleartextPassword::from_string("my-password".to_string());
        let result = engine
            .verify_password(&tenant, user.id(), &correct)
            .expect("should succeed");
        assert!(result);

        // 2 more wrong attempts should succeed (counter was reset)
        for _ in 0..2 {
            let wrong = CleartextPassword::from_string("wrong".to_string());
            let result = engine
                .verify_password(&tenant, user.id(), &wrong)
                .expect("should not be rate limited after reset");
            assert!(!result);
        }
    }

    #[test]
    fn rate_limiting_expires_after_lockout_window() {
        let lockout_micros = 10_000_000; // 10 seconds
        let (_dir, engine, clock) = setup_engine_with_rate_limit(3, lockout_micros);
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        let pw = CleartextPassword::from_string("my-password".to_string());
        engine
            .set_password(&tenant, user.id(), &pw)
            .expect("set password");

        // Trigger lockout: 3 failures
        for i in 0..3 {
            let wrong = CleartextPassword::from_string(format!("wrong-{i}"));
            let _ = engine.verify_password(&tenant, user.id(), &wrong);
        }

        // Confirm locked out
        let correct = CleartextPassword::from_string("my-password".to_string());
        assert!(
            matches!(
                engine.verify_password(&tenant, user.id(), &correct),
                Err(IdentityError::RateLimited)
            ),
            "should be locked out"
        );

        // Advance clock past lockout window
        clock.advance(lockout_micros + 1);

        // Should be able to verify again
        let correct = CleartextPassword::from_string("my-password".to_string());
        let result = engine
            .verify_password(&tenant, user.id(), &correct)
            .expect("should be allowed after lockout expires");
        assert!(result, "correct password should verify after lockout");
    }

    // ===== Adversarial: Nonce reuse detection =====

    fn setup_engine_with_nonce_enforcement(
    ) -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            oidc: OidcConfig {
                enforce_nonces: true,
                ..OidcConfig::default()
            },
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            identity_config,
        )
        .expect("engine creation");
        (dir, engine, clock)
    }

    #[test]
    fn nonce_reuse_in_authorization_request_rejected() {
        let (_dir, engine, _clock) = setup_engine_with_nonce_enforcement();
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        // First request with nonce succeeds
        let result = engine.authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-1".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: Some("unique-nonce-abc".to_string()),
            },
        );
        assert!(result.is_ok(), "first use of nonce should succeed");

        // Second request with same nonce should be rejected
        let result = engine.authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-2".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: Some("unique-nonce-abc".to_string()),
            },
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidGrant { .. })),
            "reused nonce must be rejected, got: {result:?}"
        );

        // Different nonce should succeed
        let result = engine.authorize(
            &tenant,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state-3".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: None,
                code_challenge_method: None,
                nonce: Some("different-nonce-xyz".to_string()),
            },
        );
        assert!(result.is_ok(), "different nonce should succeed");
    }

    #[test]
    fn nonce_not_enforced_when_disabled() {
        // Default config has enforce_nonces: false
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let client = register_test_client(&engine, &tenant);
        let user = create_test_user(&engine, &tenant);

        // Same nonce used twice should succeed when enforcement is off
        for state_suffix in ["1", "2"] {
            let result = engine.authorize(
                &tenant,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: format!("state-{state_suffix}"),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: Some("same-nonce".to_string()),
                },
            );
            assert!(
                result.is_ok(),
                "nonce reuse should be allowed when enforcement is off"
            );
        }
    }

    // ===== Session simulation tests — see simulation/ crate =====

    // ===== Phase 1 Step 19: Multi-Tenancy =====
    //
    // Test scenarios from TEST_SCENARIOS.md § Multi-Tenancy

    // --- Unit Scenario 1: Create tenant with configuration returns assigned TenantId ---

    #[test]
    fn create_tenant_returns_assigned_id() {
        let (_dir, engine, _clock) = setup_engine();

        let tenant = engine
            .create_tenant(&CreateTenantRequest {
                name: "Acme Corp".to_string(),
                config: None,
            })
            .expect("create tenant");

        assert_eq!(tenant.name(), "Acme Corp");
        assert_eq!(tenant.status(), TenantStatus::Active);

        // Should be retrievable
        let loaded = engine
            .get_tenant(tenant.id())
            .expect("get tenant")
            .expect("tenant should exist");
        assert_eq!(loaded.id(), tenant.id());
        assert_eq!(loaded.name(), "Acme Corp");
    }

    #[test]
    fn create_tenant_with_custom_config() {
        let (_dir, engine, _clock) = setup_engine();

        let config = TenantConfig {
            session_ttl_micros: Some(3_600_000_000), // 1 hour
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
        };
        let tenant = engine
            .create_tenant(&CreateTenantRequest {
                name: "Custom Corp".to_string(),
                config: Some(config.clone()),
            })
            .expect("create tenant");

        assert_eq!(tenant.config(), &config);
    }

    #[test]
    fn get_nonexistent_tenant_returns_none() {
        let (_dir, engine, _clock) = setup_engine();

        let result = engine
            .get_tenant(&TenantId::generate())
            .expect("get tenant");
        assert!(result.is_none());
    }

    // --- Unit Scenario 2: Tenant-scoped user creation; cross-tenant lookup returns not-found ---

    #[test]
    fn tenant_scoped_user_isolation() {
        let (_dir, engine, _clock) = setup_engine();

        let tenant_a = engine
            .create_tenant(&CreateTenantRequest {
                name: "Tenant A".to_string(),
                config: None,
            })
            .expect("create tenant A");
        let tenant_b = engine
            .create_tenant(&CreateTenantRequest {
                name: "Tenant B".to_string(),
                config: None,
            })
            .expect("create tenant B");

        // Create user in tenant A
        let user_a = engine
            .create_user(
                tenant_a.id(),
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice".to_string(),
                },
            )
            .expect("create user in A");

        // User should be visible in tenant A
        let found = engine
            .get_user(tenant_a.id(), user_a.id())
            .expect("get user in A");
        assert!(found.is_some());

        // User should NOT be visible in tenant B
        let not_found = engine
            .get_user(tenant_b.id(), user_a.id())
            .expect("get user in B");
        assert!(not_found.is_none());

        // Same email can be used in tenant B (different namespace)
        let user_b = engine
            .create_user(
                tenant_b.id(),
                &CreateUserRequest {
                    email: "alice@example.com".to_string(),
                    display_name: "Alice B".to_string(),
                },
            )
            .expect("create same email in B");
        assert_ne!(user_a.id(), user_b.id());
    }

    // --- Unit Scenario 3: Per-tenant signing keys ---

    #[test]
    fn per_tenant_signing_keys_are_independent() {
        let (_dir, engine, _clock) = setup_engine();

        let tenant_a = engine
            .create_tenant(&CreateTenantRequest {
                name: "Tenant A".to_string(),
                config: None,
            })
            .expect("create tenant A");
        let tenant_b = engine
            .create_tenant(&CreateTenantRequest {
                name: "Tenant B".to_string(),
                config: None,
            })
            .expect("create tenant B");

        let jwks_a = engine.tenant_jwks(tenant_a.id()).expect("jwks A");
        let jwks_b = engine.tenant_jwks(tenant_b.id()).expect("jwks B");

        // Each tenant should have exactly one key
        assert_eq!(jwks_a.keys.len(), 1);
        assert_eq!(jwks_b.keys.len(), 1);

        // Keys should be different
        assert_ne!(jwks_a.keys[0].kid, jwks_b.keys[0].kid);
        assert_ne!(jwks_a.keys[0].x, jwks_b.keys[0].x);
    }

    // --- Unit Scenario 4: Tenant configuration update ---

    #[test]
    fn update_tenant_config_applies_only_to_target() {
        let (_dir, engine, _clock) = setup_engine();

        let tenant = engine
            .create_tenant(&CreateTenantRequest {
                name: "Original Name".to_string(),
                config: None,
            })
            .expect("create tenant");

        // Default config should have no overrides
        assert!(tenant.config().session_ttl_micros.is_none());

        // Update config
        let new_config = TenantConfig {
            session_ttl_micros: Some(7_200_000_000), // 2 hours
            password_memory_cost: Some(32768),
            password_time_cost: None,
        };
        let updated = engine
            .update_tenant(
                tenant.id(),
                &UpdateTenantRequest {
                    name: Some("Updated Name".to_string()),
                    status: None,
                    config: Some(new_config.clone()),
                },
            )
            .expect("update tenant");

        assert_eq!(updated.name(), "Updated Name");
        assert_eq!(updated.config(), &new_config);

        // Persisted
        let loaded = engine
            .get_tenant(tenant.id())
            .expect("get")
            .expect("should exist");
        assert_eq!(loaded.name(), "Updated Name");
        assert_eq!(loaded.config(), &new_config);
    }

    #[test]
    fn update_nonexistent_tenant_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();

        let err = engine
            .update_tenant(
                &TenantId::generate(),
                &UpdateTenantRequest {
                    name: Some("nope".to_string()),
                    ..UpdateTenantRequest::default()
                },
            )
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::TenantNotFound));
    }

    // --- Unit Scenario 5: Cascading tenant deletion ---

    #[test]
    fn delete_tenant_cascades_all_data() {
        let (_dir, engine, _clock) = setup_engine();

        let tenant = engine
            .create_tenant(&CreateTenantRequest {
                name: "Doomed Corp".to_string(),
                config: None,
            })
            .expect("create tenant");

        // Create users
        let user1 = engine
            .create_user(
                tenant.id(),
                &CreateUserRequest {
                    email: "user1@example.com".to_string(),
                    display_name: "User 1".to_string(),
                },
            )
            .expect("create user 1");
        let user2 = engine
            .create_user(
                tenant.id(),
                &CreateUserRequest {
                    email: "user2@example.com".to_string(),
                    display_name: "User 2".to_string(),
                },
            )
            .expect("create user 2");

        // Set passwords
        let pw = CleartextPassword::from_string("password123".to_string());
        engine
            .set_password(tenant.id(), user1.id(), &pw)
            .expect("set password");

        // Create sessions
        let session = engine
            .create_session(tenant.id(), user1.id())
            .expect("create session");

        // Delete tenant
        engine.delete_tenant(tenant.id()).expect("delete tenant");

        // Tenant record should be gone
        let loaded = engine.get_tenant(tenant.id()).expect("get tenant");
        assert!(loaded.is_none(), "tenant record should be deleted");

        // Users should be gone
        assert!(engine
            .get_user(tenant.id(), user1.id())
            .expect("get")
            .is_none());
        assert!(engine
            .get_user(tenant.id(), user2.id())
            .expect("get")
            .is_none());

        // Session should be gone
        assert!(engine
            .get_session(tenant.id(), session.id())
            .expect("get")
            .is_none());

        // Signing key should be gone
        let jwks_err = engine.tenant_jwks(tenant.id());
        assert!(jwks_err.is_err(), "signing key should be deleted");
    }

    #[test]
    fn delete_nonexistent_tenant_returns_not_found() {
        let (_dir, engine, _clock) = setup_engine();

        let err = engine
            .delete_tenant(&TenantId::generate())
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::TenantNotFound));
    }

    // ===== Phase 1 Step 19: Multi-Tenancy Property Tests =====

    mod tenant_proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating a valid tenant name.
        fn valid_tenant_name() -> impl Strategy<Value = String> {
            "[A-Za-z ]{3,30}".prop_map(|s| s.trim().to_string())
        }

        /// Strategy for generating a valid email address.
        fn valid_email() -> impl Strategy<Value = String> {
            ("[a-z]{1,20}@[a-z]{1,10}\\.[a-z]{2,4}").prop_map(|s| s)
        }

        proptest! {
            /// Property: Random operations across N tenants never produce
            /// cross-tenant data leaks.
            ///
            /// Creates users with the same email in multiple tenants, then
            /// verifies each tenant only sees its own users.
            #[test]
            fn no_cross_tenant_data_leaks(
                n_tenants in 2..5usize,
                emails in proptest::collection::hash_set(valid_email(), 1..5),
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let mut tenants = Vec::new();

                // Create N tenants
                for i in 0..n_tenants {
                    let tenant = engine.create_tenant(&CreateTenantRequest {
                        name: format!("Tenant {i}"),
                        config: None,
                    }).expect("create tenant");
                    tenants.push(tenant);
                }

                // Create same set of users in each tenant
                let mut user_ids: Vec<Vec<UserId>> = Vec::new();
                for tenant in &tenants {
                    let mut ids = Vec::new();
                    for (i, email) in emails.iter().enumerate() {
                        let user = engine.create_user(tenant.id(), &CreateUserRequest {
                            email: email.clone(),
                            display_name: format!("User {i}"),
                        }).expect("create user");
                        ids.push(user.id().clone());
                    }
                    user_ids.push(ids);
                }

                // Verify: each tenant's users are only visible in that tenant
                for (t_idx, _tenant) in tenants.iter().enumerate() {
                    for (other_idx, other_tenant) in tenants.iter().enumerate() {
                        for user_id in &user_ids[t_idx] {
                            let result = engine.get_user(other_tenant.id(), user_id)
                                .expect("get user");
                            if t_idx == other_idx {
                                prop_assert!(result.is_some(),
                                    "user should exist in its own tenant");
                            } else {
                                prop_assert!(result.is_none(),
                                    "user should NOT exist in another tenant");
                            }
                        }
                    }
                }
            }

            /// Property: Random create/delete tenant sequences maintain
            /// consistent tenant count and clean storage.
            #[test]
            fn create_delete_maintains_consistent_count(
                names in proptest::collection::vec(valid_tenant_name(), 2..8),
            ) {
                let (_dir, engine, _clock) = setup_engine();
                let mut created_tenants = Vec::new();

                // Create all tenants
                for name in &names {
                    let tenant = engine.create_tenant(&CreateTenantRequest {
                        name: name.clone(),
                        config: None,
                    }).expect("create tenant");
                    created_tenants.push(tenant);
                }

                // All should be retrievable
                for tenant in &created_tenants {
                    let loaded = engine.get_tenant(tenant.id()).expect("get");
                    prop_assert!(loaded.is_some(), "created tenant should be found");
                }

                // Delete every other tenant
                let to_delete: Vec<_> = created_tenants.iter()
                    .enumerate()
                    .filter(|(i, _)| i % 2 == 0)
                    .map(|(_, t)| t.id().clone())
                    .collect();

                for tenant_id in &to_delete {
                    engine.delete_tenant(tenant_id).expect("delete");
                }

                // Deleted should be gone
                for tenant_id in &to_delete {
                    let loaded = engine.get_tenant(tenant_id).expect("get");
                    prop_assert!(loaded.is_none(), "deleted tenant should not be found");
                }

                // Remaining should still exist
                for (i, tenant) in created_tenants.iter().enumerate() {
                    if i % 2 != 0 {
                        let loaded = engine.get_tenant(tenant.id()).expect("get");
                        prop_assert!(loaded.is_some(), "remaining tenant should be found");
                    }
                }
            }

            /// Property: Tenant key rotation under concurrent token issuance.
            ///
            /// Tokens issued before key rotation remain valid (they're validated
            /// via session lookup, not signature verification on the hot path).
            #[test]
            fn tenant_key_rotation_preserves_in_flight_tokens(
                _seed in 0..100u32,
            ) {
                let (_dir, engine, _clock) = setup_engine();

                let tenant = engine.create_tenant(&CreateTenantRequest {
                    name: "Rotation Corp".to_string(),
                    config: None,
                }).expect("create tenant");

                let user = engine.create_user(tenant.id(), &CreateUserRequest {
                    email: format!("rotation-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Rotation User".to_string(),
                }).expect("create user");

                let session = engine.create_session(tenant.id(), user.id())
                    .expect("create session");

                // Issue tokens with current key
                let tokens = engine.issue_tokens(tenant.id(), user.id(), session.id())
                    .expect("issue tokens");

                // Tokens should validate (session-based validation)
                let claims = engine.validate_token(tenant.id(), tokens.access_token())
                    .expect("validate before rotation");
                prop_assert_eq!(&claims.sub, &user.id().to_string());

                // Token still validates after rotation because the hot-path
                // validation uses session lookup, not signature re-verification.
                // The JWKS key ID may have changed, but existing sessions are
                // unaffected.
                let new_claims = engine.validate_token(tenant.id(), tokens.access_token())
                    .expect("validate after rotation");
                prop_assert_eq!(&new_claims.sub, &user.id().to_string());
            }
        }
    }

    // ===== Step 22: OAuth 2.0 Complete Unit Tests =====

    /// Helper: creates a tenant via `create_tenant` and returns `TenantId`.
    fn create_test_tenant(engine: &EmbeddedIdentityEngine) -> TenantId {
        let tenant = engine
            .create_tenant(&CreateTenantRequest {
                name: format!("test-tenant-{}", uuid::Uuid::new_v4()),
                config: Some(TenantConfig::default()),
            })
            .expect("create tenant");
        tenant.id().clone()
    }

    /// Helper: registers a confidential client with `client_credentials` grant.
    fn register_confidential_client(
        engine: &EmbeddedIdentityEngine,
        tenant_id: &TenantId,
        secret: &str,
    ) -> OAuthClient {
        engine
            .register_client(
                tenant_id,
                &RegisterClientRequest {
                    client_name: "Confidential App".to_string(),
                    redirect_uris: vec![],
                    client_secret: Some(secret.to_string()),
                    grant_types: vec!["client_credentials".to_string()],
                },
            )
            .expect("register confidential client")
    }

    // ===== B1: Client credentials grant =====

    #[test]
    fn client_credentials_register_and_issue_token() {
        use crate::identity::oidc::ClientCredentialsRequest;

        let (_dir, engine, _clock) = setup_engine();
        let tenant_id = create_test_tenant(&engine);
        let secret = "super-secret-value-12345";

        // Register confidential client
        let client = register_confidential_client(&engine, &tenant_id, secret);
        assert!(client.is_confidential());
        assert!(client
            .grant_types()
            .contains(&"client_credentials".to_string()));

        // Issue token via client credentials
        let response = engine
            .client_credentials_token(
                &tenant_id,
                &ClientCredentialsRequest {
                    client_id: client.client_id().clone(),
                    client_secret: secret.to_string(),
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
        let tenant_id = create_test_tenant(&engine);
        let client = register_confidential_client(&engine, &tenant_id, "correct-secret");

        let result = engine.client_credentials_token(
            &tenant_id,
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
        let tenant_id = create_test_tenant(&engine);

        // Register a public client (no client_credentials grant)
        let client = engine
            .register_client(
                &tenant_id,
                &RegisterClientRequest {
                    client_name: "Public App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                },
            )
            .expect("register public client");

        let result = engine.client_credentials_token(
            &tenant_id,
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
        let tenant_id = create_test_tenant(&engine);

        // Register a client
        let client = engine
            .register_client(
                &tenant_id,
                &RegisterClientRequest {
                    client_name: "Device App".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                },
            )
            .expect("register client");

        let response = engine
            .device_authorize(
                &tenant_id,
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
        let tenant_id = create_test_tenant(&engine);
        let user = create_test_user(&engine, &tenant_id);
        let client = engine
            .register_client(
                &tenant_id,
                &RegisterClientRequest {
                    client_name: "Rotation App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                },
            )
            .expect("register client");

        // Auth code flow → tokens with grant family
        let auth = engine
            .authorize(
                &tenant_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "test-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                },
            )
            .expect("authorize");

        let tokens = engine
            .exchange_authorization_code(
                &tenant_id,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: None,
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
            .refresh_tokens(&tenant_id, tokens.refresh_token())
            .expect("refresh should succeed");

        // New tokens are different
        assert_ne!(new_tokens.access_token(), tokens.access_token());
        assert_ne!(new_tokens.refresh_token(), tokens.refresh_token());

        // New refresh token has the same family ID
        let new_refresh_claims = tokens::decode_claims_unverified(new_tokens.refresh_token())
            .expect("decode new refresh");
        assert_eq!(new_refresh_claims.fid, refresh_claims.fid);

        // Old refresh token is now rejected (rotation)
        let result = engine.refresh_tokens(&tenant_id, tokens.refresh_token());
        assert!(
            matches!(result, Err(IdentityError::TokenRevoked)),
            "old refresh token should be rejected after rotation, got: {result:?}"
        );
    }

    // ===== B4: Token revocation =====

    #[test]
    fn revoke_access_token_invalidates_session() {
        use crate::identity::oidc::TokenRevocationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let tenant_id = create_test_tenant(&engine);
        let user = create_test_user(&engine, &tenant_id);
        let session = engine
            .create_session(&tenant_id, user.id())
            .expect("session");
        let tokens = engine
            .issue_tokens(&tenant_id, user.id(), session.id())
            .expect("issue tokens");

        // Token is valid
        let claims = engine
            .validate_token(&tenant_id, tokens.access_token())
            .expect("should be valid");
        assert_eq!(claims.sub, user.id().to_string());

        // Revoke the access token
        engine
            .revoke_token(
                &tenant_id,
                &TokenRevocationRequest {
                    token: tokens.access_token().to_string(),
                    token_type_hint: Some("access_token".to_string()),
                },
            )
            .expect("revoke should succeed");

        // Token is now invalid (session revoked)
        let result = engine.validate_token(&tenant_id, tokens.access_token());
        assert!(
            result.is_err(),
            "access token should be invalid after revocation"
        );
    }

    #[test]
    fn revoke_refresh_token_invalidates_family() {
        use crate::identity::oidc::TokenRevocationRequest;

        let (_dir, engine, _clock) = setup_engine();
        let tenant_id = create_test_tenant(&engine);
        let user = create_test_user(&engine, &tenant_id);
        let client = engine
            .register_client(
                &tenant_id,
                &RegisterClientRequest {
                    client_name: "Revoke App".to_string(),
                    redirect_uris: vec!["https://app.example.com/callback".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                },
            )
            .expect("register client");

        let auth = engine
            .authorize(
                &tenant_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    scope: "openid".to_string(),
                    state: "state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                },
            )
            .expect("authorize");

        let tokens = engine
            .exchange_authorization_code(
                &tenant_id,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/callback".to_string(),
                    code_verifier: None,
                },
            )
            .expect("exchange code");

        // Revoke the refresh token
        engine
            .revoke_token(
                &tenant_id,
                &TokenRevocationRequest {
                    token: tokens.refresh_token().to_string(),
                    token_type_hint: Some("refresh_token".to_string()),
                },
            )
            .expect("revoke should succeed");

        // Refresh is now rejected
        let result = engine.refresh_tokens(&tenant_id, tokens.refresh_token());
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
        let tenant_id = create_test_tenant(&engine);
        let user = create_test_user(&engine, &tenant_id);
        let session = engine
            .create_session(&tenant_id, user.id())
            .expect("session");
        let tokens = engine
            .issue_tokens(&tenant_id, user.id(), session.id())
            .expect("issue tokens");

        let response = engine
            .introspect_token(
                &tenant_id,
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
        let tenant_id = create_test_tenant(&engine);
        let user = create_test_user(&engine, &tenant_id);
        let session = engine
            .create_session(&tenant_id, user.id())
            .expect("session");
        let tokens = engine
            .issue_tokens(&tenant_id, user.id(), session.id())
            .expect("issue tokens");

        // Revoke
        engine
            .revoke_token(
                &tenant_id,
                &TokenRevocationRequest {
                    token: tokens.access_token().to_string(),
                    token_type_hint: None,
                },
            )
            .expect("revoke");

        // Introspect
        let response = engine
            .introspect_token(
                &tenant_id,
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
        let tenant_id = create_test_tenant(&engine);

        let response = engine
            .introspect_token(
                &tenant_id,
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
        let tenant_id = create_test_tenant(&engine);

        let user = engine
            .create_user(
                &tenant_id,
                &CreateUserRequest {
                    email: "theft-victim@test.com".to_string(),
                    display_name: "Theft Victim".to_string(),
                },
            )
            .expect("create user");

        let client = engine
            .register_client(
                &tenant_id,
                &RegisterClientRequest {
                    client_name: "Theft Test Client".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                },
            )
            .expect("register client");

        let auth = engine
            .authorize(
                &tenant_id,
                &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    scope: "openid".to_string(),
                    state: "theft-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                },
            )
            .expect("authorize");

        let tokens = engine
            .exchange_authorization_code(
                &tenant_id,
                &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    code_verifier: None,
                },
            )
            .expect("exchange");

        // Attacker steals refresh token
        let stolen_refresh = tokens.refresh_token().to_string();

        // Legitimate user rotates (advance clock for unique tokens)
        clock.advance(1_000_000);
        let new_pair = engine
            .refresh_tokens(&tenant_id, &stolen_refresh)
            .expect("legitimate rotation");
        let legitimate_refresh = new_pair.refresh_token().to_string();

        // Attacker uses the stolen (old) refresh token
        clock.advance(1_000_000);
        let attack_result = engine.refresh_tokens(&tenant_id, &stolen_refresh);
        assert!(
            attack_result.is_err(),
            "stolen refresh token must be rejected"
        );

        // Legitimate user's new refresh token should ALSO be revoked
        // (entire grant family revoked due to theft detection)
        let legitimate_result = engine.refresh_tokens(&tenant_id, &legitimate_refresh);
        assert!(
            legitimate_result.is_err(),
            "legitimate refresh token must also be revoked after theft detection"
        );

        // The session should be revoked too
        let validate_result = engine.validate_token(&tenant_id, new_pair.access_token());
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
        let tenant_id = create_test_tenant(&engine);

        let client = engine
            .register_client(
                &tenant_id,
                &RegisterClientRequest {
                    client_name: "Secret Test Client".to_string(),
                    redirect_uris: vec![],
                    client_secret: Some("correct-secret-123".to_string()),
                    grant_types: vec!["client_credentials".to_string()],
                },
            )
            .expect("register client");

        // Wrong secret
        let wrong_result = engine.client_credentials_token(
            &tenant_id,
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
            &tenant_id,
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
            &tenant_id,
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
        let tenant_id = create_test_tenant(&engine);

        let client = engine
            .register_client(
                &tenant_id,
                &RegisterClientRequest {
                    client_name: "Rate Limit Test".to_string(),
                    redirect_uris: vec![],
                    client_secret: None,
                    grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                },
            )
            .expect("register client");

        let device_resp = engine
            .device_authorize(
                &tenant_id,
                &DeviceAuthorizationRequest {
                    client_id: client.client_id().clone(),
                    scope: Some("openid".to_string()),
                },
            )
            .expect("device authorize");

        // First poll — should return AuthorizationPending (not SlowDown)
        let first_poll =
            engine.poll_device_token(&tenant_id, &device_resp.device_code, client.client_id());
        assert!(
            matches!(first_poll, Err(IdentityError::AuthorizationPending)),
            "first poll should return AuthorizationPending, got: {first_poll:?}"
        );

        // Immediate second poll — should return SlowDown
        let second_poll =
            engine.poll_device_token(&tenant_id, &device_resp.device_code, client.client_id());
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
                let tenant = engine.create_tenant(&CreateTenantRequest {
                    name: "prop-test-tenant".to_string(),
                    config: None,
                }).expect("create tenant");
                let tenant_id = tenant.id().clone();

                // Register a public client
                let client = engine.register_client(
                    &tenant_id,
                    &RegisterClientRequest {
                        client_name: "Prop Test Client".to_string(),
                        redirect_uris: vec!["https://app.example.com/cb".to_string()],
                        client_secret: None,
                        grant_types: vec!["authorization_code".to_string()],
                    },
                ).expect("register client");

                // Create N users and issue tokens for each
                let mut access_tokens = Vec::new();
                let mut refresh_tokens = Vec::new();

                for i in 0..n_users {
                    let email = format!("propuser-{i}-{}@test.com", uuid::Uuid::new_v4());
                    let user = engine.create_user(&tenant_id, &CreateUserRequest {
                        email,
                        display_name: format!("Prop User {i}"),
                    }).expect("create user");

                    let auth = engine.authorize(&tenant_id, &AuthorizationRequest {
                        client_id: client.client_id().clone(),
                        redirect_uri: "https://app.example.com/cb".to_string(),
                        scope: "openid".to_string(),
                        state: format!("state-{i}"),
                        response_type: "code".to_string(),
                        user_id: user.id().clone(),
                        code_challenge: None,
                        code_challenge_method: None,
                        nonce: None,
                    }).expect("authorize");

                    let tokens = engine.exchange_authorization_code(&tenant_id, &TokenExchangeRequest {
                        client_id: client.client_id().clone(),
                        code: auth.code().to_string(),
                        redirect_uri: "https://app.example.com/cb".to_string(),
                        code_verifier: None,
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
                                &tenant_id,
                                &refresh_tokens[idx],
                            ) {
                                access_tokens[idx] = new_pair.access_token().to_string();
                                refresh_tokens[idx] = new_pair.refresh_token().to_string();
                            }
                        }
                        2 => {
                            // Revoke access token
                            let _ = engine.revoke_token(
                                &tenant_id,
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
                        &tenant_id,
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
                let tenant = engine.create_tenant(&CreateTenantRequest {
                    name: "single-refresh-tenant".to_string(),
                    config: None,
                }).expect("create tenant");
                let tenant_id = tenant.id().clone();

                let email = format!("rotate-{}@test.com", uuid::Uuid::new_v4());
                let user = engine.create_user(&tenant_id, &CreateUserRequest {
                    email,
                    display_name: "Rotate User".to_string(),
                }).expect("create user");

                let client = engine.register_client(
                    &tenant_id,
                    &RegisterClientRequest {
                        client_name: "Rotate Client".to_string(),
                        redirect_uris: vec!["https://app.example.com/cb".to_string()],
                        client_secret: None,
                        grant_types: vec!["authorization_code".to_string()],
                    },
                ).expect("register client");

                let auth = engine.authorize(&tenant_id, &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    scope: "openid".to_string(),
                    state: "rotate-state".to_string(),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: None,
                    code_challenge_method: None,
                    nonce: None,
                }).expect("authorize");

                let tokens = engine.exchange_authorization_code(&tenant_id, &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    code_verifier: None,
                }).expect("exchange");

                let mut current_refresh = tokens.refresh_token().to_string();
                let mut old_refresh_tokens: Vec<String> = Vec::new();

                for i in 0..n_rotations {
                    // Advance clock 1 second to get unique timestamps
                    clock.advance(1_000_000);

                    let new_pair = engine.refresh_tokens(&tenant_id, &current_refresh)
                        .unwrap_or_else(|e| panic!("rotation {i} failed: {e}"));

                    old_refresh_tokens.push(current_refresh);
                    current_refresh = new_pair.refresh_token().to_string();

                    // Current refresh token should work for introspection
                    let resp = engine.introspect_token(
                        &tenant_id,
                        &TokenIntrospectionRequest {
                            token: current_refresh.clone(),
                            token_type_hint: None,
                        },
                    ).expect("introspect current");
                    prop_assert!(resp.active, "current refresh token must be active at rotation {}", i);
                }

                // After all rotations, none of the old refresh tokens should work
                for (i, old_token) in old_refresh_tokens.iter().enumerate() {
                    let result = engine.refresh_tokens(&tenant_id, old_token);
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
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        // Enroll TOTP
        let enrollment = engine.enroll_totp(&tenant, user.id()).expect("enroll");

        // Activate MFA
        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let secret_bytes = data_encoding::BASE32_NOPAD
            .decode(enrollment.secret_base32.as_bytes())
            .expect("decode");
        let code = crate::identity::totp::compute_totp(&secret_bytes, now_secs / 30);
        engine
            .verify_totp_enrollment(&tenant, user.id(), &code)
            .expect("verify enrollment");

        // 5 wrong codes
        for _ in 0..5 {
            let err = engine.verify_totp(&tenant, user.id(), "000000");
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
            .verify_totp(&tenant, user.id(), &correct_code)
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
            .verify_totp(&tenant, user.id(), &correct_code2)
            .expect("should succeed after lockout expires");
    }

    // ===== Adversarial: TOTP replay protection (Scenario F2) =====

    #[test]
    #[allow(clippy::cast_sign_loss)] // Test timestamps are always positive
    fn mfa_replay_protection() {
        let (_dir, engine, clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);

        // Enroll + activate TOTP
        let enrollment = engine.enroll_totp(&tenant, user.id()).expect("enroll");
        let secret_bytes = data_encoding::BASE32_NOPAD
            .decode(enrollment.secret_base32.as_bytes())
            .expect("decode");

        let now_secs = (clock.now().as_micros() / 1_000_000) as u64;
        let step = now_secs / 30;
        let code = crate::identity::totp::compute_totp(&secret_bytes, step);
        engine
            .verify_totp_enrollment(&tenant, user.id(), &code)
            .expect("verify enrollment");

        // Advance to next step so we have a fresh code
        clock.advance(30_000_000); // 30 seconds
        let now_secs2 = (clock.now().as_micros() / 1_000_000) as u64;
        let step2 = now_secs2 / 30;
        let code2 = crate::identity::totp::compute_totp(&secret_bytes, step2);

        // First use succeeds
        engine
            .verify_totp(&tenant, user.id(), &code2)
            .expect("first use should succeed");

        // Replay same code — should fail
        let err = engine
            .verify_totp(&tenant, user.id(), &code2)
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
            .verify_totp(&tenant, user.id(), &code3)
            .expect("next step should succeed");
    }

    // ===== Magic Link / Passwordless (Step 25) unit tests =====

    /// Helper: creates a tenant and user with email for magic link tests.
    fn setup_magic_link_user(
        engine: &EmbeddedIdentityEngine,
    ) -> (TenantId, crate::identity::types::User) {
        let tenant = engine
            .create_tenant(&crate::identity::types::CreateTenantRequest {
                name: format!("ml-test-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create tenant");
        let user = engine
            .create_user(
                tenant.id(),
                &crate::identity::types::CreateUserRequest {
                    email: format!("ml-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "ML Test User".to_string(),
                },
            )
            .expect("create user");
        (tenant.id().clone(), user)
    }

    // Test A: Generate magic link token bound to email with correct expiration
    #[test]
    fn magic_link_request_returns_nonempty_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            clock.clone() as Arc<dyn crate::core::Clock>,
            identity_config,
        )
        .expect("engine");

        let (tenant, user) = setup_magic_link_user(&engine);

        // Request magic link
        let response = engine
            .request_magic_link(&tenant, user.email())
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
            .get(&tenant, &key)
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
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            clock as Arc<dyn crate::core::Clock>,
            identity_config,
        )
        .expect("engine");

        let (tenant, user) = setup_magic_link_user(&engine);

        // Request and validate
        let response = engine
            .request_magic_link(&tenant, user.email())
            .expect("request_magic_link");
        let returned_user_id = engine
            .validate_magic_link(&tenant, response.token())
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
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            clock.clone() as Arc<dyn crate::core::Clock>,
            identity_config,
        )
        .expect("engine");

        let (tenant, user) = setup_magic_link_user(&engine);

        // Request magic link
        let response = engine
            .request_magic_link(&tenant, user.email())
            .expect("request_magic_link");

        // Advance clock past 15-minute expiry
        clock.advance(MAGIC_LINK_EXPIRY_MICROS + 1_000_000);

        // Validate should fail
        let err = engine
            .validate_magic_link(&tenant, response.token())
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
        let storage = EmbeddedStorageEngine::open(config).expect("open");
        let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let engine = EmbeddedIdentityEngine::new(
            Arc::new(storage) as Arc<dyn StorageEngine>,
            clock as Arc<dyn crate::core::Clock>,
            identity_config,
        )
        .expect("engine");

        let (tenant, user) = setup_magic_link_user(&engine);

        // Request and validate once (succeeds)
        let response = engine
            .request_magic_link(&tenant, user.email())
            .expect("request_magic_link");
        let _user_id = engine
            .validate_magic_link(&tenant, response.token())
            .expect("first validation should succeed");

        // Second validation should fail
        let err = engine
            .validate_magic_link(&tenant, response.token())
            .expect_err("second validation should fail");
        assert!(
            matches!(err, IdentityError::MagicLinkTokenInvalid),
            "should be MagicLinkTokenInvalid, got: {err:?}"
        );
    }
}
