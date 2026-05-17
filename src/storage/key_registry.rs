//! Key registry for per-realm Key Encryption Keys (KEKs).
//!
//! Manages the two-level envelope encryption hierarchy:
//!
//! ```text
//! Host Key (from HEARTH_MASTER_KEY env var or auto-generated file)
//!   └── Realm KEKs (stored encrypted in hearth.keys)
//!         └── File DEKs (stored wrapped in SST/WAL headers)
//!               └── File data (encrypted with DEK)
//! ```
//!
//! KEKs are persisted in `{data_dir}/hearth.keys` with integrity framing:
//!
//! ```text
//! [2B]  Version (0x0001, u16 LE)
//! Per-entry:
//!   [16B] RealmId UUID bytes
//!   [4B]  Encrypted KEK length (u32 LE)
//!   [NB]  Encrypted KEK (nonce + ciphertext + tag from encrypt_kek)
//!   [4B]  CRC32 of preceding entry bytes (UUID + length + encrypted KEK)
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::core::RealmId;
use crate::storage::encryption::{
    decrypt_kek, encrypt_kek, generate_host_key, generate_kek, HostKey, KekId, KeyEncryptionKey,
    KEK_ID_SIZE,
};
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, RealFs};

/// File version: 2 bytes, u16 LE.
const KEY_FILE_VERSION: u16 = 0x0001;
const KEY_FILE_VERSION_SIZE: usize = 2;

/// Maps realm IDs to their decrypted KEKs.
type KekMap = HashMap<RealmId, KeyEncryptionKey>;

/// Manages per-realm Key Encryption Keys.
///
/// Thread-safe via a `std::sync::Mutex`. KEK operations are off the hot path
/// (only during startup, realm creation, and key rotation).
pub(crate) struct KeyRegistry {
    /// Host key loaded from environment or auto-generated.
    host_key: HostKey,
    /// In-memory map of realm ID → decrypted KEK.
    keks: Mutex<KekMap>,
    /// Path to the `hearth.keys` persistence file.
    key_file_path: PathBuf,
    /// File handle for appending KEK entries (fsync'd on write).
    key_file: Mutex<Option<Box<dyn crate::storage::fs::FsFile>>>,
    /// Filesystem abstraction.
    fs: Arc<dyn Fs>,
}

impl KeyRegistry {
    /// Loads or creates the key registry.
    pub(crate) fn load(data_dir: &Path) -> Result<Self, StorageError> {
        Self::load_with_fs(data_dir, Arc::new(RealFs))
    }

    /// Loads the key registry with a custom filesystem.
    pub(crate) fn load_with_fs(data_dir: &Path, fs: Arc<dyn Fs>) -> Result<Self, StorageError> {
        fs.create_dir_all(data_dir)?;
        let host_key = load_or_create_host_key(data_dir, &*fs)?;
        let prev_host_key = load_previous_host_key()?;
        Self::load_with_keys(data_dir, fs, host_key, prev_host_key)
    }

    /// Loads the key registry with explicit host keys (used directly in tests).
    pub(crate) fn load_with_keys(
        data_dir: &Path,
        fs: Arc<dyn Fs>,
        host_key: HostKey,
        prev_host_key: Option<HostKey>,
    ) -> Result<Self, StorageError> {
        let key_file_path = data_dir.join("hearth.keys");

        let load_result = if key_file_path.exists() {
            load_keks_from_file(&key_file_path, &host_key, prev_host_key.as_ref(), &*fs)?
        } else {
            LoadKeksResult::empty()
        };

        // Block startup when any KEK cannot be decrypted with either key.
        if !load_result.failed.is_empty() {
            let affected_realms = load_result
                .failed
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>();
            return Err(StorageError::HostKeyMismatch { affected_realms });
        }

        let keks = load_result.keks;

        // Re-encrypt KEKs that were decrypted with the previous host key, then
        // rewrite hearth.keys atomically so the old key is no longer needed.
        let key_file: Option<Box<dyn crate::storage::fs::FsFile>> =
            if !load_result.needs_reencrypt.is_empty() {
                tracing::info!(
                    count = load_result.needs_reencrypt.len(),
                    "HEARTH_PREVIOUS_MASTER_KEY: re-encrypting realm KEKs under new master key"
                );
                Some(rewrite_keys_file(&key_file_path, &keks, &host_key, &*fs)?)
            } else if key_file_path.exists() {
                Some(fs.open_append(&key_file_path)?)
            } else {
                None
            };

        Ok(Self {
            host_key,
            keks: Mutex::new(keks),
            key_file_path,
            key_file: Mutex::new(key_file),
            fs,
        })
    }

    /// Returns the KEK identifier for a realm (its UUID bytes).
    pub(crate) fn kek_id_for_realm(&self, realm_id: &RealmId) -> KekId {
        let mut id = [0u8; KEK_ID_SIZE];
        let uuid_bytes = realm_id.as_uuid().as_bytes();
        id.copy_from_slice(uuid_bytes);
        id
    }

    /// Returns the decrypted KEK for a realm, if it exists.
    pub(crate) fn get_kek_for_realm(&self, realm_id: &RealmId) -> Option<KeyEncryptionKey> {
        let keks = self.keks.lock().ok()?;
        keks.get(realm_id).map(|k| k.clone_key())
    }

    /// Returns true if a KEK exists for the given realm.
    #[allow(dead_code)]
    pub(crate) fn has_kek_for_realm(&self, realm_id: &RealmId) -> bool {
        self.keks
            .lock()
            .map(|k| k.contains_key(realm_id))
            .unwrap_or(false)
    }

    /// Ensures a realm has a KEK, generating one if it doesn't exist.
    ///
    /// Returns the KEK. On first creation for a realm, the KEK is persisted
    /// to `hearth.keys` immediately with fsync.
    pub(crate) fn ensure_kek_for_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<KeyEncryptionKey, StorageError> {
        {
            let keks = self.keks.lock().map_err(|_| StorageError::Crypto {
                reason: "KEK map mutex poisoned".to_string(),
            })?;
            if let Some(kek) = keks.get(realm_id) {
                return Ok(kek.clone_key());
            }
        }

        // Generate new KEK
        let new_kek = generate_kek()?;
        let kek_id = self.kek_id_for_realm(realm_id);
        let encrypted = encrypt_kek(&new_kek, &self.host_key, kek_id)?;

        // Persist to hearth.keys with fsync
        self.append_kek_entry(realm_id, &encrypted)?;

        // Store in memory
        {
            let mut keks = self.keks.lock().map_err(|_| StorageError::Crypto {
                reason: "KEK map mutex poisoned".to_string(),
            })?;
            keks.insert(realm_id.clone(), new_kek.clone_key());
        }

        Ok(new_kek)
    }

    /// Rotates the KEK for a realm: generates a new KEK and persists it.
    ///
    /// Returns `(old_kek, new_kek)`. The caller is responsible for re-wrapping
    /// all DEKs in SST/WAL files with the new KEK.
    #[allow(dead_code)]
    pub(crate) fn rotate_kek(
        &self,
        realm_id: &RealmId,
    ) -> Result<(KeyEncryptionKey, KeyEncryptionKey), StorageError> {
        let old_kek = {
            let keks = self.keks.lock().map_err(|_| StorageError::Crypto {
                reason: "KEK map mutex poisoned".to_string(),
            })?;
            keks.get(realm_id)
                .map(|k| k.clone_key())
                .ok_or_else(|| StorageError::Crypto {
                    reason: format!("no KEK for realm {realm_id}"),
                })?
        };

        let new_kek = generate_kek()?;
        let kek_id = self.kek_id_for_realm(realm_id);
        let encrypted = encrypt_kek(&new_kek, &self.host_key, kek_id)?;

        // Persist new KEK with fsync
        self.append_kek_entry(realm_id, &encrypted)?;

        // Update in memory
        {
            let mut keks = self.keks.lock().map_err(|_| StorageError::Crypto {
                reason: "KEK map mutex poisoned".to_string(),
            })?;
            keks.insert(realm_id.clone(), new_kek.clone_key());
        }

        Ok((old_kek, new_kek))
    }

    /// Appends a KEK entry to `hearth.keys` with CRC32 framing and fsync.
    fn append_kek_entry(
        &self,
        realm_id: &RealmId,
        encrypted_kek: &[u8],
    ) -> Result<(), StorageError> {
        #[allow(clippy::cast_possible_truncation)]
        let entry_len = encrypted_kek.len() as u32;

        // Build entry: [uuid(16)][length(4)][encrypted(N)][crc32(4)]
        let mut entry = Vec::with_capacity(16 + 4 + encrypted_kek.len() + 4);
        entry.extend_from_slice(realm_id.as_uuid().as_bytes());
        entry.extend_from_slice(&entry_len.to_le_bytes());
        entry.extend_from_slice(encrypted_kek);

        // Compute CRC32 over preceding bytes
        let crc = crc32fast::hash(&entry);
        entry.extend_from_slice(&crc.to_le_bytes());

        let mut file_guard = self.key_file.lock().map_err(|_| StorageError::Crypto {
            reason: "key file mutex poisoned".to_string(),
        })?;

        if file_guard.is_none() {
            // Create key file with version header
            *file_guard = Some(self.fs.create(&self.key_file_path)?);
            let version_bytes = KEY_FILE_VERSION.to_le_bytes();
            file_guard
                .as_mut()
                .ok_or_else(|| StorageError::Crypto {
                    reason: "failed to create key file".to_string(),
                })?
                .write_all(&version_bytes)?;
        }

        let f = file_guard.as_mut().ok_or_else(|| StorageError::Crypto {
            reason: "key file handle lost".to_string(),
        })?;
        f.write_all(&entry)?;
        f.sync_all()?;

        Ok(())
    }
}

impl std::fmt::Debug for KeyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.keks.lock().map(|k| k.len()).unwrap_or(0);
        f.debug_struct("KeyRegistry")
            .field("key_file_path", &self.key_file_path)
            .field("loaded_realms", &count)
            .finish_non_exhaustive()
    }
}

/// Result of loading KEKs from `hearth.keys`.
struct LoadKeksResult {
    keks: KekMap,
    /// Realms whose KEK was decrypted with the *previous* host key; need re-encryption.
    needs_reencrypt: Vec<RealmId>,
    /// Realms whose KEK passed CRC but could not be decrypted with either key.
    failed: Vec<RealmId>,
}

impl LoadKeksResult {
    fn empty() -> Self {
        Self {
            keks: KekMap::new(),
            needs_reencrypt: Vec::new(),
            failed: Vec::new(),
        }
    }
}

/// Loads or creates the host key.
///
/// Priority:
/// 1. `HEARTH_MASTER_KEY` environment variable (hex-encoded 32-byte key)
/// 2. `{data_dir}/hearth.host_key` file (32 raw bytes)
/// 3. Auto-generate and persist to `{data_dir}/hearth.host_key`
fn load_or_create_host_key(data_dir: &Path, fs: &dyn Fs) -> Result<HostKey, StorageError> {
    // 1. Check environment variable
    if let Ok(env_val) = std::env::var("HEARTH_MASTER_KEY") {
        let env_val = env_val.trim();
        if env_val.len() == 64 {
            let bytes = decode_hex(env_val).map_err(|_| StorageError::Crypto {
                reason: "HEARTH_MASTER_KEY is not valid hex".to_string(),
            })?;
            return Ok(HostKey::from_bytes(bytes));
        }
        return Err(StorageError::Crypto {
            reason: "HEARTH_MASTER_KEY must be 64 hex chars".to_string(),
        });
    }

    // 2. Check file
    let host_key_path = data_dir.join("hearth.host_key");
    if host_key_path.exists() {
        let data = fs.read(&host_key_path)?;
        if data.len() != 32 {
            return Err(StorageError::Crypto {
                reason: format!(
                    "hearth.host_key has wrong length: {} bytes (expected 32)",
                    data.len()
                ),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);
        return Ok(HostKey::from_bytes(bytes));
    }

    // 3. Auto-generate
    let host_key = generate_host_key()?;
    fs.write(&host_key_path, host_key.as_bytes())?;

    Ok(host_key)
}

/// Loads the previous host key from `HEARTH_PREVIOUS_MASTER_KEY`, if set.
fn load_previous_host_key() -> Result<Option<HostKey>, StorageError> {
    let Ok(env_val) = std::env::var("HEARTH_PREVIOUS_MASTER_KEY") else {
        return Ok(None);
    };
    let env_val = env_val.trim().to_owned();
    if env_val.len() == 64 {
        let bytes = decode_hex(&env_val).map_err(|_| StorageError::Crypto {
            reason: "HEARTH_PREVIOUS_MASTER_KEY is not valid hex".to_string(),
        })?;
        return Ok(Some(HostKey::from_bytes(bytes)));
    }
    Err(StorageError::Crypto {
        reason: "HEARTH_PREVIOUS_MASTER_KEY must be 64 hex chars".to_string(),
    })
}

/// Rewrites `hearth.keys` atomically with all KEKs encrypted under `host_key`.
///
/// Uses write-to-tmp → fsync → rename to guarantee crash safety.
/// Returns an open append handle to the rewritten file.
fn rewrite_keys_file(
    path: &Path,
    keks: &KekMap,
    host_key: &HostKey,
    fs: &dyn Fs,
) -> Result<Box<dyn crate::storage::fs::FsFile>, StorageError> {
    let mut content = Vec::new();
    content.extend_from_slice(&KEY_FILE_VERSION.to_le_bytes());

    for (realm_id, kek) in keks {
        let kek_id: KekId = {
            let mut id = [0u8; KEK_ID_SIZE];
            id.copy_from_slice(realm_id.as_uuid().as_bytes());
            id
        };
        let encrypted = encrypt_kek(kek, host_key, kek_id)?;
        #[allow(clippy::cast_possible_truncation)]
        let entry_len = encrypted.len() as u32;

        let mut entry = Vec::with_capacity(16 + 4 + encrypted.len() + 4);
        entry.extend_from_slice(realm_id.as_uuid().as_bytes());
        entry.extend_from_slice(&entry_len.to_le_bytes());
        entry.extend_from_slice(&encrypted);
        let crc = crc32fast::hash(&entry);
        entry.extend_from_slice(&crc.to_le_bytes());
        content.extend_from_slice(&entry);
    }

    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp_path = parent.join("hearth.keys.tmp");

    {
        let mut tmp_file = fs.create(&tmp_path)?;
        tmp_file.write_all(&content)?;
        tmp_file.sync_all()?;
    }

    fs.rename(&tmp_path, path)?;
    Ok(fs.open_append(path)?)
}

/// Loads realm KEKs from `hearth.keys` with CRC32 integrity verification.
///
/// If decryption fails with `host_key` and `prev_host_key` is provided,
/// falls back to the previous key. Realms decrypted via the fallback are
/// recorded in `needs_reencrypt`; realms that fail both keys go to `failed`.
fn load_keks_from_file(
    path: &Path,
    host_key: &HostKey,
    prev_host_key: Option<&HostKey>,
    fs: &dyn Fs,
) -> Result<LoadKeksResult, StorageError> {
    let data = fs.read(path)?;

    // File must have at least version header + one entry
    if data.len() < KEY_FILE_VERSION_SIZE {
        return Ok(LoadKeksResult::empty());
    }

    let version = u16::from_le_bytes(data[..KEY_FILE_VERSION_SIZE].try_into().map_err(|_| {
        StorageError::Crypto {
            reason: "truncated version in hearth.keys".to_string(),
        }
    })?);
    if version != KEY_FILE_VERSION {
        return Err(StorageError::Crypto {
            reason: format!("unsupported hearth.keys version: {version}"),
        });
    }

    let mut result = LoadKeksResult::empty();
    let mut pos = KEY_FILE_VERSION_SIZE;

    while pos + 20 + 4 <= data.len() {
        let entry_start = pos;

        // Read realm UUID (16 bytes)
        let uuid_bytes: [u8; 16] =
            data[pos..pos + 16]
                .try_into()
                .map_err(|_| StorageError::Crypto {
                    reason: "truncated realm UUID in hearth.keys".to_string(),
                })?;
        let realm_id = RealmId::new(uuid::Uuid::from_bytes(uuid_bytes));
        pos += 16;

        // Read entry length (4 bytes, u32 LE)
        if pos + 4 > data.len() {
            break;
        }
        let entry_len =
            u32::from_le_bytes(
                data[pos..pos + 4]
                    .try_into()
                    .map_err(|_| StorageError::Crypto {
                        reason: "invalid entry length in hearth.keys".to_string(),
                    })?,
            ) as usize;
        pos += 4;

        // Read encrypted KEK
        if pos + entry_len > data.len() {
            break;
        }
        pos += entry_len; // bytes consumed (we reference the slice below)

        // Read CRC32 (4 bytes)
        if pos + 4 > data.len() {
            break;
        }
        let stored_crc = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| {
            StorageError::Crypto {
                reason: "truncated CRC in hearth.keys".to_string(),
            }
        })?);
        pos += 4;

        // Verify CRC32 over [UUID(16)][length(4)][encrypted(N)]
        let entry_bytes = &data[entry_start..pos - 4];
        let computed_crc = crc32fast::hash(entry_bytes);
        if stored_crc != computed_crc {
            tracing::warn!(
                realm_id = %realm_id,
                "hearth.keys: CRC mismatch for entry; skipping corrupted entry"
            );
            continue;
        }

        // Try current host key first; fall back to previous host key on failure.
        let encrypted_kek = &data[entry_start + 16 + 4..entry_start + 16 + 4 + entry_len];
        let kek_id: KekId = {
            let mut id = [0u8; KEK_ID_SIZE];
            id.copy_from_slice(realm_id.as_uuid().as_bytes());
            id
        };
        match decrypt_kek(encrypted_kek, host_key, kek_id) {
            Ok(kek) => {
                // Last entry for a realm wins (supports rotation).
                result.keks.insert(realm_id, kek);
            }
            Err(_) => {
                // Current key failed — try previous key if provided.
                if let Some(prev_key) = prev_host_key {
                    match decrypt_kek(encrypted_kek, prev_key, kek_id) {
                        Ok(kek) => {
                            tracing::info!(
                                realm_id = %realm_id,
                                "decrypted KEK with previous host key; will re-encrypt"
                            );
                            result.needs_reencrypt.push(realm_id.clone());
                            result.keks.insert(realm_id, kek);
                        }
                        Err(_) => {
                            tracing::error!(
                                realm_id = %realm_id,
                                "hearth.keys: KEK cannot be decrypted with current or previous key"
                            );
                            result.failed.push(realm_id);
                        }
                    }
                } else {
                    tracing::error!(
                        realm_id = %realm_id,
                        "hearth.keys: KEK cannot be decrypted with current key; \
                         set HEARTH_PREVIOUS_MASTER_KEY if you rotated the master key"
                    );
                    result.failed.push(realm_id);
                }
            }
        }
    }

    Ok(result)
}

/// Decodes a hex string into a 32-byte array.
fn decode_hex(s: &str) -> Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk.first().copied().unwrap_or(b'0'))?;
        let lo = hex_val(chunk.get(1).copied().unwrap_or(b'0'))?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(bytes)
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;

    #[test]
    fn key_registry_ensure_kek_creates_and_retrieves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = KeyRegistry::load(dir.path()).expect("load");

        let realm = RealmId::generate();
        let kek = registry.ensure_kek_for_realm(&realm).expect("ensure kek");

        let retrieved = registry.get_kek_for_realm(&realm).expect("get kek");
        assert_eq!(kek.as_bytes(), retrieved.as_bytes());
    }

    #[test]
    fn key_registry_persists_across_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Create realm KEK
        {
            let registry = KeyRegistry::load(dir.path()).expect("load");
            let kek = registry.ensure_kek_for_realm(&realm).expect("ensure kek");
            let retrieved = registry.get_kek_for_realm(&realm).expect("get kek");
            assert_eq!(kek.as_bytes(), retrieved.as_bytes());
        }

        // Re-load and verify KEK survives
        {
            let registry = KeyRegistry::load(dir.path()).expect("reload");
            let kek = registry
                .get_kek_for_realm(&realm)
                .expect("should have kek after reload");
            assert_eq!(kek.as_bytes().len(), 32);
        }
    }

    #[test]
    fn key_registry_rotate_kek_produces_new_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = KeyRegistry::load(dir.path()).expect("load");
        let realm = RealmId::generate();

        let kek1 = registry.ensure_kek_for_realm(&realm).expect("ensure");

        let (old_kek, new_kek) = registry.rotate_kek(&realm).expect("rotate");

        assert_eq!(old_kek.as_bytes(), kek1.as_bytes());
        assert_ne!(new_kek.as_bytes(), kek1.as_bytes());

        let retrieved = registry
            .get_kek_for_realm(&realm)
            .expect("get after rotate");
        assert_eq!(retrieved.as_bytes(), new_kek.as_bytes());
    }

    #[test]
    fn key_registry_different_realms_have_different_keks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = KeyRegistry::load(dir.path()).expect("load");

        let realm1 = RealmId::generate();
        let realm2 = RealmId::generate();

        let kek1 = registry.ensure_kek_for_realm(&realm1).expect("ensure 1");
        let kek2 = registry.ensure_kek_for_realm(&realm2).expect("ensure 2");

        assert_ne!(kek1.as_bytes(), kek2.as_bytes());
    }

    #[test]
    fn key_registry_kek_id_matches_realm_uuid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = KeyRegistry::load(dir.path()).expect("load");
        let realm = RealmId::generate();

        let expected_kek_id: KekId = {
            let mut id = [0u8; KEK_ID_SIZE];
            id.copy_from_slice(realm.as_uuid().as_bytes());
            id
        };
        let actual_kek_id = registry.kek_id_for_realm(&realm);

        assert_eq!(expected_kek_id, actual_kek_id);
    }

    #[test]
    fn key_registry_crc_corruption_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Create a valid KEK
        {
            let registry = KeyRegistry::load(dir.path()).expect("load");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Corrupt the CRC of the last entry
        {
            let key_file = dir.path().join("hearth.keys");
            let mut data = std::fs::read(&key_file).expect("read keys");
            // Corrupt last 4 bytes (CRC)
            let len = data.len();
            data[len - 1] ^= 0xFF;
            data[len - 2] ^= 0xFF;
            std::fs::write(&key_file, &data).expect("write corrupt");
        }

        // Re-load: corrupted entry should be skipped, realm has no KEK
        {
            let registry = KeyRegistry::load(dir.path()).expect("reload");
            assert!(
                registry.get_kek_for_realm(&realm).is_none(),
                "corrupted entry should be skipped"
            );
        }
    }

    #[test]
    fn key_registry_partial_write_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // Create a valid KEK
        {
            let registry = KeyRegistry::load(dir.path()).expect("load");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Truncate the file to simulate partial write (cut CRC in half)
        {
            let key_file = dir.path().join("hearth.keys");
            let data = std::fs::read(&key_file).expect("read keys");
            // Truncate last 2 bytes
            let truncated = &data[..data.len() - 2];
            std::fs::write(&key_file, truncated).expect("write truncated");
        }

        // Re-load: truncated entry should be skipped (incomplete CRC)
        {
            let registry = KeyRegistry::load(dir.path()).expect("reload");
            assert!(
                registry.get_kek_for_realm(&realm).is_none(),
                "truncated entry should be skipped"
            );
        }
    }

    // ── Host key rotation tests ───────────────────────────────────────────────

    fn make_test_key_bytes() -> [u8; 32] {
        use crate::storage::encryption::generate_host_key;
        *generate_host_key().expect("generate host key").as_bytes()
    }

    fn mk(bytes: [u8; 32]) -> HostKey {
        HostKey::from_bytes(bytes)
    }

    fn load_with_two_keys(
        dir: &std::path::Path,
        current: [u8; 32],
        previous: Option<[u8; 32]>,
    ) -> Result<KeyRegistry, StorageError> {
        KeyRegistry::load_with_keys(
            dir,
            Arc::new(crate::storage::fs::RealFs),
            mk(current),
            previous.map(mk),
        )
    }

    #[test]
    fn host_key_rotation_re_encrypts_keks_and_new_key_works_standalone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();

        // Record the KEK value under key1 so we can compare after rotation.
        let original_kek_bytes = {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("load1");
            let kek = registry.ensure_kek_for_realm(&realm).expect("ensure");
            kek.as_bytes().to_vec()
        };

        // Load with key2 (current) + key1 (previous) → auto re-encrypts.
        {
            let registry =
                load_with_two_keys(dir.path(), key2, Some(key1)).expect("load with rotation");
            let kek = registry
                .get_kek_for_realm(&realm)
                .expect("kek accessible during rotation");
            assert_eq!(
                kek.as_bytes(),
                original_kek_bytes.as_slice(),
                "KEK value unchanged after re-encryption"
            );
        }

        // Load with key2 alone (no previous) → succeeds because file was rewritten.
        {
            let registry = load_with_two_keys(dir.path(), key2, None).expect("load after rewrite");
            let kek = registry
                .get_kek_for_realm(&realm)
                .expect("kek accessible after re-encryption");
            assert_eq!(
                kek.as_bytes(),
                original_kek_bytes.as_slice(),
                "KEK value unchanged after standalone reload"
            );
        }
    }

    #[test]
    fn host_key_rotation_missing_previous_key_blocks_startup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();

        // Create realm KEK under key1.
        {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("load1");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Load with key2 but no previous key → must fail with HostKeyMismatch.
        let err = load_with_two_keys(dir.path(), key2, None)
            .expect_err("should block startup when previous key is missing");
        match err {
            StorageError::HostKeyMismatch { affected_realms } => {
                assert!(
                    !affected_realms.is_empty(),
                    "affected_realms must name at least one realm"
                );
            }
            other => panic!("expected HostKeyMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn host_key_rotation_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();

        // Create KEK under key1.
        {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("load1");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // First rotation: key2 + key1 as previous.
        let kek_after_first = {
            let registry = load_with_two_keys(dir.path(), key2, Some(key1)).expect("rotation 1");
            registry
                .get_kek_for_realm(&realm)
                .expect("kek after rotation 1")
                .as_bytes()
                .to_vec()
        };

        // Second load with same key2, no previous → idempotent (file already rewritten).
        {
            let registry = load_with_two_keys(dir.path(), key2, None).expect("idempotent reload");
            let kek = registry
                .get_kek_for_realm(&realm)
                .expect("kek on second load");
            assert_eq!(
                kek.as_bytes(),
                kek_after_first.as_slice(),
                "KEK unchanged on second load"
            );
        }
    }

    #[test]
    fn host_key_rotation_crc_corrupt_entries_still_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();

        // Create KEK under key1.
        {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("load");
            registry.ensure_kek_for_realm(&realm).expect("ensure");
        }

        // Corrupt the CRC of the entry.
        {
            let key_file = dir.path().join("hearth.keys");
            let mut data = std::fs::read(&key_file).expect("read");
            let len = data.len();
            data[len - 1] ^= 0xFF;
            std::fs::write(&key_file, &data).expect("write corrupt");
        }

        // CRC-corrupt entry should be skipped — not treated as a decryption
        // failure — so HostKeyMismatch must NOT be returned even with a wrong key.
        let registry = load_with_two_keys(dir.path(), key2, None)
            .expect("CRC-corrupt entries must not trigger HostKeyMismatch");
        assert!(
            registry.get_kek_for_realm(&realm).is_none(),
            "CRC-corrupt entry is skipped; realm has no KEK"
        );
    }

    #[test]
    fn host_key_rotation_multi_realm_partial_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        let key1 = make_test_key_bytes();
        let key2 = make_test_key_bytes();
        let key3 = make_test_key_bytes();

        // realm_a under key1.
        {
            let registry = load_with_two_keys(dir.path(), key1, None).expect("a");
            registry.ensure_kek_for_realm(&realm_a).expect("ensure a");
        }
        // Rotate key1→key2; add realm_b under key2.
        {
            let registry = load_with_two_keys(dir.path(), key2, Some(key1)).expect("b");
            registry.ensure_kek_for_realm(&realm_b).expect("ensure b");
        }

        // Now load with key3 + no previous: both realms fail → HostKeyMismatch.
        let err = load_with_two_keys(dir.path(), key3, None).expect_err("both realms should fail");
        match err {
            StorageError::HostKeyMismatch { affected_realms } => {
                assert_eq!(affected_realms.len(), 2, "both realms should be reported");
            }
            other => panic!("expected HostKeyMismatch, got: {other:?}"),
        }
    }
}
