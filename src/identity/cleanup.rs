//! Periodic cleanup of expired OAuth entities.
//!
//! Sweeps expired authorization codes, device codes, pending
//! authorization tickets, and grant families from storage. Called by a
//! background task at a configurable interval.
//!
//! # Race semantics
//!
//! The sweeper may delete a code between issue and redemption.
//! `exchange_authorization_code()` returns `InvalidAuthorizationCode`
//! for missing keys — identical error to a legitimate double-submit.
//! OAuth clients must already handle `invalid_grant` responses.
//!
//! Device code polling returns `DeviceCodeExpired` (`expired_token`)
//! for missing keys, so a swept device code surfaces as a clean expiry.

use crate::core::{Clock, RealmId, Timestamp};
use crate::identity::keys;
use crate::identity::oidc::{StoredDeviceCode, StoredGrantFamily};
use crate::identity::types::PendingAuthorizationRequest;
use crate::storage::StorageEngine;

/// Configuration for the periodic cleanup sweeper.
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Whether periodic cleanup is enabled.
    pub enabled: bool,
    /// Interval in seconds between cleanup sweeps. 0 disables the
    /// background task even when `enabled` is true.
    pub interval_secs: u64,
    /// Maximum entities to delete per type per sweep. Bounds worst-case
    /// sweep latency on the first run after feature enablement.
    pub max_per_type: usize,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 300,
            max_per_type: 1000,
        }
    }
}

/// Deletion counts from a single sweep pass.
#[derive(Debug, Default, Clone)]
pub struct CleanupStats {
    /// Authorization codes swept.
    pub auth_codes_deleted: u64,
    /// Device codes swept.
    pub device_codes_deleted: u64,
    /// Pending authorization tickets swept.
    pub pending_tickets_deleted: u64,
    /// Grant families swept.
    pub grant_families_deleted: u64,
    /// Number of entity-type sweeps that encountered an error.
    pub errors: u64,
}

impl CleanupStats {
    /// Total entities deleted across all types.
    pub fn total_deleted(&self) -> u64 {
        self.auth_codes_deleted
            + self.device_codes_deleted
            + self.pending_tickets_deleted
            + self.grant_families_deleted
    }
}

/// Runs all entity-type sweeps for a single realm.
///
/// Errors from individual sweeps are logged and counted in
/// [`CleanupStats::errors`]; the function always returns `CleanupStats`
/// (best-effort). The next tick retries any failed sweeps.
pub(crate) fn sweep_expired(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    clock: &dyn Clock,
    config: &CleanupConfig,
) -> CleanupStats {
    let mut stats = CleanupStats::default();
    let now = clock.now();

    match sweep_auth_codes(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.auth_codes_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: auth code sweep failed"
            );
        }
    }

    match sweep_device_codes(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.device_codes_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: device code sweep failed"
            );
        }
    }

    match sweep_pending_tickets(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.pending_tickets_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: pending ticket sweep failed"
            );
        }
    }

    match sweep_grant_families(realm_id, storage, now, config.max_per_type) {
        Ok(n) => stats.grant_families_deleted = n,
        Err(e) => {
            stats.errors += 1;
            tracing::warn!(
                realm = %realm_id,
                error = %e,
                "cleanup: grant family sweep failed"
            );
        }
    }

    stats
}

// --- per-entity sweep helpers ---

fn sweep_auth_codes(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    #[derive(serde::Deserialize)]
    struct Expiry {
        expires_at: Timestamp,
    }

    let prefix = keys::oauth_code_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }

        let exp: Expiry = serde_json::from_slice(&entry.value).map_err(|e| {
            crate::storage::StorageError::DeserializationFailed {
                reason: format!("cleanup: failed to deserialize auth code: {e}"),
            }
        })?;

        if now >= exp.expires_at {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }

    Ok(deleted)
}

fn sweep_device_codes(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::device_code_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }
        let stored: StoredDeviceCode = serde_json::from_slice(&entry.value).map_err(|e| {
            crate::storage::StorageError::DeserializationFailed {
                reason: format!("cleanup: failed to deserialize device code: {e}"),
            }
        })?;

        if now >= stored.expires_at {
            storage.delete(realm_id, &entry.key)?;
            // Also clean up the user_code → device_code index.
            // An orphaned index is benign garbage, but we make a
            // best-effort attempt to remove it.
            let uc_key = keys::encode_user_code(&stored.user_code);
            if let Err(e) = storage.delete(realm_id, &uc_key) {
                tracing::warn!(
                    realm = %realm_id,
                    user_code = %stored.user_code,
                    error = %e,
                    "cleanup: failed to delete user_code index for expired device code",
                );
            }
            deleted += 1;
        }
    }

    Ok(deleted)
}

fn sweep_pending_tickets(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::oauth_pending_auth_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }
        let ticket: PendingAuthorizationRequest =
            serde_json::from_slice(&entry.value).map_err(|e| {
                crate::storage::StorageError::DeserializationFailed {
                    reason: format!("cleanup: failed to deserialize pending ticket: {e}"),
                }
            })?;

        if now >= ticket.expires_at {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }

    Ok(deleted)
}

fn sweep_grant_families(
    realm_id: &RealmId,
    storage: &dyn StorageEngine,
    now: Timestamp,
    max_per_type: usize,
) -> Result<u64, crate::storage::StorageError> {
    let prefix = keys::grant_family_scan_prefix();
    let end = keys::prefix_end(&prefix);
    let entries = storage.scan(realm_id, &prefix, &end)?;

    let mut deleted: u64 = 0;
    for entry in &entries {
        if deleted >= max_per_type as u64 {
            break;
        }
        let family: StoredGrantFamily = serde_json::from_slice(&entry.value).map_err(|e| {
            crate::storage::StorageError::DeserializationFailed {
                reason: format!("cleanup: failed to deserialize grant family: {e}"),
            }
        })?;

        if now >= family.expires_at {
            storage.delete(realm_id, &entry.key)?;
            deleted += 1;
        }
    }

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FakeClock, Timestamp};
    use crate::identity::keys;
    use crate::identity::oidc::{DeviceCodeStatus, StoredAuthorizationCode, StoredDeviceCode};
    use crate::identity::types::PendingAuthorizationRequest;
    use crate::storage::EmbeddedStorageEngine;

    fn storage() -> (EmbeddedStorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let engine = EmbeddedStorageEngine::open(crate::storage::StorageConfig::dev(
            dir.path().to_path_buf(),
        ))
        .expect("open storage");
        (engine, dir)
    }

    fn fake_clock(micros: i64) -> FakeClock {
        FakeClock::new(Timestamp::from_micros(micros))
    }

    const T0: i64 = 1_700_000_000_000_000; // base timestamp in micros
    const ONE_HOUR: i64 = 3_600_000_000;
    const TEN_MINUTES: i64 = 600_000_000;

    // --- auth codes ---

    #[test]
    fn sweep_auth_codes_deletes_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let code = StoredAuthorizationCode {
            code_hash: "hash1".into(),
            client_id: crate::core::ClientId::generate(),
            user_id: crate::core::UserId::generate(),
            redirect_uri: "https://ex.com/cb".into(),
            scope: "openid".into(),
            code_challenge: None,
            code_challenge_method: None,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            used: false,
            nonce: None,
        };
        let key = keys::encode_oauth_code("hash1");
        s.put(&realm, &key, &serde_json::to_vec(&code).expect("serialize"))
            .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.auth_codes_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
    }

    #[test]
    fn sweep_auth_codes_keeps_valid() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + TEN_MINUTES / 2);

        let code = StoredAuthorizationCode {
            code_hash: "hash2".into(),
            client_id: crate::core::ClientId::generate(),
            user_id: crate::core::UserId::generate(),
            redirect_uri: "https://ex.com/cb".into(),
            scope: "openid".into(),
            code_challenge: None,
            code_challenge_method: None,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            used: false,
            nonce: None,
        };
        let key = keys::encode_oauth_code("hash2");
        s.put(&realm, &key, &serde_json::to_vec(&code).expect("serialize"))
            .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.auth_codes_deleted, 0);
        assert!(s.get(&realm, &key).expect("get").is_some());
    }

    // --- device codes ---

    #[test]
    fn sweep_device_codes_deletes_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let dc = StoredDeviceCode {
            device_code_hash: "dch1".into(),
            user_code: "BDFGJKMN".into(),
            client_id: crate::core::ClientId::generate(),
            realm_id: realm.clone(),
            scope: Some("openid".into()),
            status: DeviceCodeStatus::Pending,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            interval: 5,
            last_polled_at: None,
        };

        let dc_key = keys::encode_device_code("dch1");
        s.put(
            &realm,
            &dc_key,
            &serde_json::to_vec(&dc).expect("serialize"),
        )
        .expect("put");
        let uc_key = keys::encode_user_code("BDFGJKMN");
        s.put(&realm, &uc_key, b"dch1").expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.device_codes_deleted, 1);
        assert!(s.get(&realm, &dc_key).expect("get").is_none());
        assert!(s.get(&realm, &uc_key).expect("get").is_none());
    }

    #[test]
    fn sweep_device_codes_keeps_valid() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + TEN_MINUTES / 2);

        let dc = StoredDeviceCode {
            device_code_hash: "dch2".into(),
            user_code: "BCDFGHJK".into(),
            client_id: crate::core::ClientId::generate(),
            realm_id: realm.clone(),
            scope: None,
            status: DeviceCodeStatus::Pending,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + ONE_HOUR),
            interval: 5,
            last_polled_at: None,
        };

        let dc_key = keys::encode_device_code("dch2");
        s.put(
            &realm,
            &dc_key,
            &serde_json::to_vec(&dc).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.device_codes_deleted, 0);
        assert!(s.get(&realm, &dc_key).expect("get").is_some());
    }

    // --- pending tickets ---

    #[test]
    fn sweep_pending_tickets_deletes_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let ticket = PendingAuthorizationRequest {
            user_id: crate::core::UserId::generate(),
            client_id: crate::core::ClientId::generate(),
            redirect_uri: "https://ex.com/cb".into(),
            requested_scopes: vec!["openid".into()],
            state: "state1".into(),
            response_type: "code".into(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
        };

        let ticket_id = uuid::Uuid::new_v4().to_string();
        let key = keys::encode_pending_auth_key(&ticket_id);
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&ticket).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.pending_tickets_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
    }

    #[test]
    fn sweep_pending_tickets_keeps_valid() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + TEN_MINUTES / 2);

        let ticket = PendingAuthorizationRequest {
            user_id: crate::core::UserId::generate(),
            client_id: crate::core::ClientId::generate(),
            redirect_uri: "https://ex.com/cb".into(),
            requested_scopes: vec!["openid".into()],
            state: "state2".into(),
            response_type: "code".into(),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + ONE_HOUR),
        };

        let ticket_id = uuid::Uuid::new_v4().to_string();
        let key = keys::encode_pending_auth_key(&ticket_id);
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&ticket).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.pending_tickets_deleted, 0);
        assert!(s.get(&realm, &key).expect("get").is_some());
    }

    // --- grant families ---

    #[test]
    fn sweep_grant_families_deletes_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let family = StoredGrantFamily {
            family_id: "fid1".into(),
            current_refresh_hash: "hash".into(),
            session_id: crate::core::SessionId::generate(),
            realm_id: realm.clone(),
            revoked: false,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            client_id: None,
        };

        let key = keys::encode_grant_family("fid1");
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&family).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.grant_families_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
    }

    #[test]
    fn sweep_grant_families_deletes_revoked_when_expired() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        let family = StoredGrantFamily {
            family_id: "fid2".into(),
            current_refresh_hash: "hash".into(),
            session_id: crate::core::SessionId::generate(),
            realm_id: realm.clone(),
            revoked: true,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
            client_id: None,
        };

        let key = keys::encode_grant_family("fid2");
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&family).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.grant_families_deleted, 1);
        assert!(s.get(&realm, &key).expect("get").is_none());
    }

    #[test]
    fn sweep_grant_families_keeps_valid() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + TEN_MINUTES / 2);

        let family = StoredGrantFamily {
            family_id: "fid3".into(),
            current_refresh_hash: "hash".into(),
            session_id: crate::core::SessionId::generate(),
            realm_id: realm.clone(),
            revoked: false,
            created_at: Timestamp::from_micros(T0),
            expires_at: Timestamp::from_micros(T0 + ONE_HOUR),
            client_id: None,
        };

        let key = keys::encode_grant_family("fid3");
        s.put(
            &realm,
            &key,
            &serde_json::to_vec(&family).expect("serialize"),
        )
        .expect("put");

        let config = CleanupConfig::default();
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.grant_families_deleted, 0);
        assert!(s.get(&realm, &key).expect("get").is_some());
    }

    // --- max_per_type ---

    #[test]
    fn sweep_respects_max_per_type() {
        let (s, _dir) = storage();
        let realm = RealmId::generate();
        let clock = fake_clock(T0 + 2 * ONE_HOUR);

        for i in 0..5 {
            let code = StoredAuthorizationCode {
                code_hash: format!("expired_hash_{i}"),
                client_id: crate::core::ClientId::generate(),
                user_id: crate::core::UserId::generate(),
                redirect_uri: "https://ex.com/cb".into(),
                scope: "openid".into(),
                code_challenge: None,
                code_challenge_method: None,
                created_at: Timestamp::from_micros(T0),
                expires_at: Timestamp::from_micros(T0 + TEN_MINUTES),
                used: false,
                nonce: None,
            };
            let key = keys::encode_oauth_code(&format!("expired_hash_{i}"));
            s.put(&realm, &key, &serde_json::to_vec(&code).expect("serialize"))
                .expect("put");
        }

        let config = CleanupConfig {
            max_per_type: 3,
            ..Default::default()
        };
        let stats = sweep_expired(&realm, &s, &clock, &config);
        assert_eq!(stats.auth_codes_deleted, 3);
    }

    // --- total deleted ---

    #[test]
    fn total_deleted_sums_all_types() {
        let stats = CleanupStats {
            auth_codes_deleted: 1,
            device_codes_deleted: 2,
            pending_tickets_deleted: 3,
            grant_families_deleted: 4,
            ..Default::default()
        };
        assert_eq!(stats.total_deleted(), 10);
    }
}
