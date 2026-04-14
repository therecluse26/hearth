//! Embedded identity engine implementation.
//!
//! Implements `IdentityEngine` using the `StorageEngine` trait for persistence
//! and `Clock` trait for deterministic timestamps.

use std::sync::Arc;

use crate::core::{Clock, TenantId, UserId};
use crate::identity::credentials::{self, CleartextPassword, CredentialConfig, StoredCredential};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::types::{CreateUserRequest, UpdateUserRequest, User, UserStatus};
use crate::identity::validation;
use crate::identity::IdentityEngine;
use crate::storage::StorageEngine;

/// Configuration for the identity engine.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Default status for newly created users.
    pub default_status: UserStatus,
    /// Password hashing parameters.
    pub credential: CredentialConfig,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            default_status: UserStatus::Active,
            credential: CredentialConfig::default(),
        }
    }
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
    /// Pre-computes a dummy Argon2id hash on construction for use in
    /// timing-oracle prevention during password verification.
    pub fn new(
        storage: Arc<dyn StorageEngine>,
        clock: Arc<dyn Clock>,
        config: IdentityConfig,
    ) -> Self {
        let dummy_hash = credentials::compute_dummy_hash(&config.credential);
        Self {
            storage,
            clock,
            config,
            dummy_hash,
        }
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

        Ok(())
    }

    fn set_password(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        password: &CleartextPassword,
    ) -> Result<(), IdentityError> {
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
        // Check user exists
        let user = self.get_user(tenant_id, user_id)?;
        if user.is_none() {
            // Timing defense: verify against dummy hash so timing is
            // indistinguishable from a real failed verification
            let _ = credentials::verify_hash(password, &self.dummy_hash);
            return Err(IdentityError::UserNotFound);
        }

        // Load credential
        let cred_key = keys::encode_credential_key(user_id);
        let cred_bytes = self
            .storage
            .get(tenant_id, &cred_key)
            .map_err(Self::storage_err)?;

        let Some(cred_bytes) = cred_bytes else {
            // Timing defense: same as above
            let _ = credentials::verify_hash(password, &self.dummy_hash);
            return Err(IdentityError::CredentialNotFound);
        };

        let cred = Self::deserialize_credential(&cred_bytes)?;
        let matches = credentials::verify_password(password, &cred)?;

        // Auto-upgrade legacy algorithms on successful verification
        if matches && cred.algorithm != credentials::PasswordAlgorithm::Argon2id {
            let now = self.clock.now().as_micros();
            let upgraded = credentials::hash_password(password, &self.config.credential, now)?;
            let upgraded_bytes = Self::serialize_credential(&upgraded)?;
            self.storage
                .put(tenant_id, &cred_key, &upgraded_bytes)
                .map_err(Self::storage_err)?;
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
        );
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
    fn verify_password_nonexistent_user_returns_error() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .verify_password(&tenant, &UserId::generate(), &pw)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
    }

    #[test]
    fn verify_password_no_credential_returns_error() {
        let (_dir, engine, _clock) = setup_engine();
        let tenant = TenantId::generate();
        let user = create_test_user(&engine, &tenant);
        let pw = CleartextPassword::from_string("password".to_string());

        let err = engine
            .verify_password(&tenant, user.id(), &pw)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::CredentialNotFound));
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

        // Verify should fail with UserNotFound, not CredentialNotFound
        let pw_check = CleartextPassword::from_string("password".to_string());
        let err = engine
            .verify_password(&tenant, user.id(), &pw_check)
            .expect_err("should fail");
        assert!(matches!(err, IdentityError::UserNotFound));
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
        }
    }
}
