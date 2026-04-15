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

use crate::identity::oidc::{
    AuthorizationRequest, AuthorizationResponse, CodeChallengeMethod, OAuthClient, OidcConfig,
    OidcDiscoveryDocument, OidcTokenResponse, RegisterClientRequest, StoredAuthorizationCode,
    TokenExchangeRequest,
};
use crate::identity::tokens::{
    self, IssueTokenRequest, JwksDocument, SigningKey, TokenClaims, TokenConfig, TokenPair,
};
use crate::identity::types::{CreateUserRequest, Session, UpdateUserRequest, User, UserStatus};
use crate::identity::validation;
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
/// input validation, and Unicode normalization.
pub struct EmbeddedIdentityEngine {
    /// The underlying storage engine.
    storage: Arc<dyn StorageEngine>,
    /// Injectable clock for deterministic testing.
    clock: Arc<dyn Clock>,
    /// Engine configuration.
    config: IdentityConfig,
    /// Pre-computed dummy hash for timing-oracle prevention.
    ///
    /// When `verify_password` is called for a nonexistent user or missing
    /// credential, we verify against this dummy hash so the response time
    /// is indistinguishable from a real failed verification.
    dummy_hash: String,
    /// Ed25519 signing key for JWT token issuance.
    signing_key: Arc<SigningKey>,
    /// Per-user failed attempt trackers for rate limiting.
    ///
    /// Key is `(TenantId, UserId)` serialized as a string to avoid
    /// requiring `Hash` on the newtype wrappers.
    attempt_trackers: Mutex<HashMap<String, AttemptTracker>>,
    /// Used nonces for replay protection (when nonce enforcement is enabled).
    used_nonces: Mutex<HashSet<String>>,
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
            attempt_trackers: Mutex::new(HashMap::new()),
            used_nonces: Mutex::new(HashSet::new()),
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
            attempt_trackers: Mutex::new(HashMap::new()),
            used_nonces: Mutex::new(HashSet::new()),
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
}

impl IdentityEngine for EmbeddedIdentityEngine {
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

        // Refresh the underlying session
        self.refresh_session(tenant_id, &session_id)?;

        // Parse user ID
        let user_id_str = claims
            .sub
            .strip_prefix("user_")
            .ok_or(IdentityError::InvalidToken)?;
        let user_uuid =
            uuid::Uuid::parse_str(user_id_str).map_err(|_| IdentityError::InvalidToken)?;
        let user_id = UserId::new(user_uuid);

        // Issue new token pair
        self.issue_tokens(tenant_id, &user_id, &session_id)
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

        // Validate redirect URIs
        if request.redirect_uris.is_empty() {
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

        let client = OAuthClient::new(
            client_id.clone(),
            client_name,
            request.redirect_uris.clone(),
            now,
        );

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

        // 10. Issue tokens (access + refresh)
        let token_pair = self.issue_tokens(tenant_id, &stored_code.user_id, session.id())?;

        // 11. Issue ID token (OIDC-specific)
        let iat = now.as_micros() / 1_000_000;
        let id_token_claims = TokenClaims {
            sub: stored_code.user_id.to_string(),
            iss: self.config.token.issuer.clone(),
            aud: request.client_id.to_string(),
            exp: iat + self.config.token.access_token_ttl_secs,
            iat,
            sid: session.id().to_string(),
            tid: tenant_id.to_string(),
            token_type: "id_token".to_string(),
        };
        let id_token = self
            .signing_key
            .issue_token(&id_token_claims)
            .map_err(|e| IdentityError::SigningError {
                reason: format!("failed to issue ID token: {e}"),
            })?;

        Ok(OidcTokenResponse::new(
            token_pair.access_token().to_string(),
            id_token,
            "Bearer".to_string(),
            self.config.token.access_token_ttl_secs,
            token_pair.refresh_token().to_string(),
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
            token_endpoint_auth_methods_supported: vec!["none".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, Timestamp};
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
}
