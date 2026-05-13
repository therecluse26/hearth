//! Encryption at rest primitives for the storage engine.
//!
//! Uses AES-256-GCM via `ring` for envelope encryption:
//! - File Data Encryption Keys (DEKs) encrypt SST/WAL data sections.
//! - Realm Key Encryption Keys (KEKs) wrap DEKs.
//! - A Host Key encrypts realm KEKs at rest in the storage engine.
//!
//! # Binary Layout
//!
//! Each encrypted SST/WAL file contains a 76-byte encryption header
//! immediately after the base file header:
//!
//! ```text
//! [16B] KEK identifier (realm UUID bytes)
//! [12B] Nonce used for DEK wrapping
//! [32B] DEK ciphertext (AES-256-GCM output of 32B plaintext)
//! [16B] GCM authentication tag for DEK wrapping
//! ```
//!
//! Key rotation re-wraps only the DEK in each file header — data sections
//! are never re-encrypted. This makes rotation O(number of files), not
//! O(total data size).

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::ZeroizeOnDrop;

use crate::storage::error::StorageError;

/// Size of an AES-256 key in bytes.
pub(crate) const KEY_SIZE: usize = 32;

/// Size of a GCM authentication tag in bytes.
pub(crate) const TAG_SIZE: usize = 16;

/// Size of a GCM nonce in bytes.
pub(crate) const NONCE_SIZE: usize = 12;

/// Size of a KEK identifier (realm UUID bytes).
pub const KEK_ID_SIZE: usize = 16;

/// Total size of the encryption extension in a file header.
/// Layout: KEK_ID(16) + nonce(12) + wrapped_dek(32 ciphertext + 16 tag) = 76 bytes.
pub const ENCRYPTION_HEADER_SIZE: usize = KEK_ID_SIZE + NONCE_SIZE + KEY_SIZE + TAG_SIZE;

/// A 32-byte Data Encryption Key used to encrypt a single SST or WAL file's
/// data section. Each file gets its own randomly generated DEK.
#[derive(ZeroizeOnDrop)]
pub struct DataEncryptionKey {
    bytes: [u8; KEY_SIZE],
}

impl DataEncryptionKey {
    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }

    /// Creates a DEK from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self { bytes }
    }
}

/// A 32-byte Key Encryption Key used to wrap (encrypt) file DEKs.
/// Each realm has its own KEK.
#[derive(ZeroizeOnDrop)]
pub struct KeyEncryptionKey {
    bytes: [u8; KEY_SIZE],
}

impl KeyEncryptionKey {
    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }

    /// Creates a KEK from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Creates an independent copy of this key.
    pub(crate) fn clone_key(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

/// A 32-byte host key that encrypts realm KEKs when stored in the engine.
/// Loaded from the `HEARTH_MASTER_KEY` environment variable or auto-generated
/// and persisted to `hearth.host_key` on first start.
#[derive(ZeroizeOnDrop)]
pub(crate) struct HostKey {
    bytes: [u8; KEY_SIZE],
}

impl HostKey {
    /// Creates a host key from raw bytes.
    pub(crate) fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns a reference to the raw key bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }
}

/// Identifies which realm KEK was used to wrap a particular file's DEK.
/// Derived from the realm's UUID.
pub type KekId = [u8; KEK_ID_SIZE];

/// Serialized encryption metadata stored in SST/WAL file headers.
///
/// Binary layout (76 bytes):
/// ```text
/// [16B] KEK identifier
/// [12B] Nonce used for DEK wrapping
/// [32B] DEK ciphertext
/// [16B] GCM authentication tag
/// ```
#[derive(Clone)]
pub struct EncryptionHeader {
    /// Identifies which realm KEK can unwrap the DEK.
    pub kek_id: KekId,
    /// Wrapped DEK bytes: 32B ciphertext followed by 16B GCM tag.
    pub wrapped_dek: [u8; KEY_SIZE + TAG_SIZE],
    /// Nonce used for the DEK wrapping operation.
    pub nonce: [u8; NONCE_SIZE],
}

impl EncryptionHeader {
    /// Serializes this header into a 76-byte buffer.
    pub(crate) fn to_bytes(&self) -> [u8; ENCRYPTION_HEADER_SIZE] {
        let mut buf = [0u8; ENCRYPTION_HEADER_SIZE];
        buf[0..16].copy_from_slice(&self.kek_id);
        buf[16..28].copy_from_slice(&self.nonce);
        buf[28..76].copy_from_slice(&self.wrapped_dek);
        buf
    }

    /// Deserializes an encryption header from a 76-byte slice.
    pub(crate) fn from_bytes(bytes: &[u8; ENCRYPTION_HEADER_SIZE]) -> Self {
        let mut kek_id = [0u8; KEK_ID_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        let mut wrapped_dek = [0u8; KEY_SIZE + TAG_SIZE];
        kek_id.copy_from_slice(&bytes[0..16]);
        nonce.copy_from_slice(&bytes[16..28]);
        wrapped_dek.copy_from_slice(&bytes[28..76]);
        Self {
            kek_id,
            wrapped_dek,
            nonce,
        }
    }
}

impl std::fmt::Debug for EncryptionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionHeader")
            .field("kek_id", &self.kek_id)
            .field("wrapped_dek", &"[redacted]")
            .field("nonce", &"[redacted]")
            .finish()
    }
}

/// Generates a random 32-byte Data Encryption Key.
pub(crate) fn generate_dek() -> Result<DataEncryptionKey, StorageError> {
    let mut bytes = [0u8; KEY_SIZE];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StorageError::Crypto {
            reason: "failed to generate random DEK".to_string(),
        })?;
    Ok(DataEncryptionKey { bytes })
}

/// Generates a random 32-byte Key Encryption Key for a realm.
pub(crate) fn generate_kek() -> Result<KeyEncryptionKey, StorageError> {
    let mut bytes = [0u8; KEY_SIZE];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StorageError::Crypto {
            reason: "failed to generate random KEK".to_string(),
        })?;
    Ok(KeyEncryptionKey { bytes })
}

/// Generates a random 32-byte host key.
pub(crate) fn generate_host_key() -> Result<HostKey, StorageError> {
    let mut bytes = [0u8; KEY_SIZE];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StorageError::Crypto {
            reason: "failed to generate random host key".to_string(),
        })?;
    Ok(HostKey { bytes })
}

/// Wraps (encrypts) a DEK using a KEK, producing an `EncryptionHeader`.
///
/// The KEK identifier (realm UUID bytes) is included as AAD during encryption
/// for domain separation, binding the wrapped DEK to a specific realm.
pub(crate) fn wrap_dek(
    dek: &DataEncryptionKey,
    kek: &KeyEncryptionKey,
    kek_id: KekId,
) -> Result<EncryptionHeader, StorageError> {
    let nonce_bytes = random_nonce()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound =
        UnboundKey::new(&AES_256_GCM, kek.as_bytes()).map_err(|_| StorageError::Crypto {
            reason: "failed to create AEAD key for DEK wrapping".to_string(),
        })?;
    let aes_key = LessSafeKey::new(unbound);

    // The DEK plaintext is the data to encrypt
    let mut buffer = dek.bytes.to_vec();
    aes_key
        .seal_in_place_append_tag(nonce, Aad::from(&kek_id), &mut buffer)
        .map_err(|_| StorageError::Crypto {
            reason: "DEK wrapping failed".to_string(),
        })?;

    // buffer now contains [32B ciphertext][16B tag]
    let mut wrapped_dek = [0u8; KEY_SIZE + TAG_SIZE];
    wrapped_dek.copy_from_slice(&buffer);

    Ok(EncryptionHeader {
        kek_id,
        wrapped_dek,
        nonce: nonce_bytes,
    })
}

/// Unwraps (decrypts) a DEK from an `EncryptionHeader` using the realm's KEK.
pub(crate) fn unwrap_dek(
    header: &EncryptionHeader,
    kek: &KeyEncryptionKey,
) -> Result<DataEncryptionKey, StorageError> {
    let nonce = Nonce::assume_unique_for_key(header.nonce);

    let unbound =
        UnboundKey::new(&AES_256_GCM, kek.as_bytes()).map_err(|_| StorageError::Crypto {
            reason: "failed to create AEAD key for DEK unwrapping".to_string(),
        })?;
    let aes_key = LessSafeKey::new(unbound);

    let mut buffer = header.wrapped_dek.to_vec();
    let plaintext = aes_key
        .open_in_place(nonce, Aad::from(&header.kek_id), &mut buffer)
        .map_err(|_| StorageError::Crypto {
            reason: "DEK unwrapping failed — wrong KEK or corrupted header".to_string(),
        })?;

    let mut bytes = [0u8; KEY_SIZE];
    bytes.copy_from_slice(plaintext);

    Ok(DataEncryptionKey { bytes })
}

/// Encrypts a data section (plaintext) using a DEK and data nonce.
///
/// The encrypted output is `plaintext` with a 16-byte GCM tag appended.
/// The `aad` parameter is used for domain separation — typically the SST
/// file number or WAL record counter bytes.
pub(crate) fn encrypt_section(
    plaintext: &[u8],
    dek: &DataEncryptionKey,
    nonce_bytes: &[u8; NONCE_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);

    let unbound =
        UnboundKey::new(&AES_256_GCM, dek.as_bytes()).map_err(|_| StorageError::Crypto {
            reason: "failed to create AEAD key for data encryption".to_string(),
        })?;
    let key = LessSafeKey::new(unbound);

    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buffer)
        .map_err(|_| StorageError::Crypto {
            reason: "data encryption failed".to_string(),
        })?;

    Ok(buffer)
}

/// Decrypts a data section (ciphertext with appended tag) using a DEK and data nonce.
pub(crate) fn decrypt_section(
    ciphertext_with_tag: &[u8],
    dek: &DataEncryptionKey,
    nonce_bytes: &[u8; NONCE_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);

    let unbound =
        UnboundKey::new(&AES_256_GCM, dek.as_bytes()).map_err(|_| StorageError::Crypto {
            reason: "failed to create AEAD key for data decryption".to_string(),
        })?;
    let key = LessSafeKey::new(unbound);

    let mut buffer = ciphertext_with_tag.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut buffer)
        .map_err(|_| StorageError::Crypto {
            reason: "data decryption failed — wrong DEK or corrupted data".to_string(),
        })?;

    Ok(plaintext.to_vec())
}

/// Re-wraps a DEK from an old KEK to a new KEK.
///
/// Used during key rotation. The DEK itself does not change — only the
/// wrapper header is updated with the new KEK. Returns a new
/// `EncryptionHeader` with the new `kek_id`, nonce, and wrapped DEK.
pub(crate) fn rewrap_header(
    header: &EncryptionHeader,
    old_kek: &KeyEncryptionKey,
    new_kek: &KeyEncryptionKey,
    new_kek_id: KekId,
) -> Result<EncryptionHeader, StorageError> {
    let dek = unwrap_dek(header, old_kek)?;
    wrap_dek(&dek, new_kek, new_kek_id)
}

/// Generates a random 12-byte nonce.
fn random_nonce() -> Result<[u8; NONCE_SIZE], StorageError> {
    let mut bytes = [0u8; NONCE_SIZE];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StorageError::Crypto {
            reason: "failed to generate random nonce".to_string(),
        })?;
    Ok(bytes)
}

/// Constructs a deterministic 12-byte data nonce from a u64 counter.
///
/// Each SST file gets a unique file number, and each WAL record gets a
/// monotonic counter. Combined with a unique per-file DEK, this ensures
/// (key, nonce) pairs are never reused — even with a deterministic nonce.
pub(crate) fn counter_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Encrypts a realm KEK with the host key for persistent storage.
///
/// The realm ID is used as AAD for domain separation.
pub(crate) fn encrypt_kek(
    kek: &KeyEncryptionKey,
    host_key: &HostKey,
    kek_id: KekId,
) -> Result<Vec<u8>, StorageError> {
    let nonce_bytes = random_nonce()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound =
        UnboundKey::new(&AES_256_GCM, host_key.as_bytes()).map_err(|_| StorageError::Crypto {
            reason: "failed to create AEAD key for KEK encryption".to_string(),
        })?;
    let aes_key = LessSafeKey::new(unbound);

    let mut buffer = kek.bytes.to_vec();
    aes_key
        .seal_in_place_append_tag(nonce, Aad::from(&kek_id), &mut buffer)
        .map_err(|_| StorageError::Crypto {
            reason: "KEK encryption failed".to_string(),
        })?;

    // Prepend the nonce to the output so we can decrypt later
    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&buffer);

    Ok(output)
}

/// Decrypts a realm KEK that was encrypted with the host key.
///
/// `encrypted_kek_with_nonce` has the nonce in the first 12 bytes followed
/// by the ciphertext with appended tag.
pub(crate) fn decrypt_kek(
    encrypted_kek_with_nonce: &[u8],
    host_key: &HostKey,
    kek_id: KekId,
) -> Result<KeyEncryptionKey, StorageError> {
    if encrypted_kek_with_nonce.len() < NONCE_SIZE + KEY_SIZE + TAG_SIZE {
        return Err(StorageError::Crypto {
            reason: "encrypted KEK too short".to_string(),
        });
    }

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(&encrypted_kek_with_nonce[..NONCE_SIZE]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound =
        UnboundKey::new(&AES_256_GCM, host_key.as_bytes()).map_err(|_| StorageError::Crypto {
            reason: "failed to create AEAD key for KEK decryption".to_string(),
        })?;
    let key = LessSafeKey::new(unbound);

    let mut buffer = encrypted_kek_with_nonce[NONCE_SIZE..].to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(&kek_id), &mut buffer)
        .map_err(|_| StorageError::Crypto {
            reason: "KEK decryption failed — wrong host key or corrupted data".to_string(),
        })?;

    let mut bytes = [0u8; KEY_SIZE];
    bytes.copy_from_slice(plaintext);

    Ok(KeyEncryptionKey { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dek_produces_32_bytes() {
        let dek = generate_dek().expect("generate");
        assert_eq!(dek.as_bytes().len(), 32);
    }

    #[test]
    fn generate_kek_produces_32_bytes() {
        let kek = generate_kek().expect("generate");
        assert_eq!(kek.as_bytes().len(), 32);
    }

    #[test]
    fn wrap_and_unwrap_dek_round_trip() {
        let dek = generate_dek().expect("dek");
        let kek = generate_kek().expect("kek");
        let kek_id = [0xAAu8; KEK_ID_SIZE];

        let header = wrap_dek(&dek, &kek, kek_id).expect("wrap");
        let unwrapped = unwrap_dek(&header, &kek).expect("unwrap");

        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn unwrap_dek_with_wrong_kek_fails() {
        let dek = generate_dek().expect("dek");
        let kek1 = generate_kek().expect("kek1");
        let kek2 = generate_kek().expect("kek2");
        let kek_id = [0xAAu8; KEK_ID_SIZE];

        let header = wrap_dek(&dek, &kek1, kek_id).expect("wrap");
        let result = unwrap_dek(&header, &kek2);

        assert!(result.is_err());
    }

    #[test]
    fn unwrap_dek_with_wrong_kek_id_fails() {
        let dek = generate_dek().expect("dek");
        let kek = generate_kek().expect("kek");
        let kek_id1 = [0xAAu8; KEK_ID_SIZE];
        let kek_id2 = [0xBBu8; KEK_ID_SIZE];

        let header = wrap_dek(&dek, &kek, kek_id1).expect("wrap");

        // Tamper with the header to change the KEK ID
        let mut tampered = header.clone();
        tampered.kek_id = kek_id2;

        // AAD mismatch should cause decryption failure
        let result = unwrap_dek(&tampered, &kek);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_and_decrypt_section_round_trip() {
        let dek = generate_dek().expect("dek");
        let nonce = counter_nonce(42);
        let aad = 42u64.to_le_bytes();
        let plaintext = b"hello world this is some test data for encryption";

        let ciphertext = encrypt_section(plaintext, &dek, &nonce, &aad).expect("encrypt");
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = decrypt_section(&ciphertext, &dek, &nonce, &aad).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_section_with_wrong_aad_fails() {
        let dek = generate_dek().expect("dek");
        let nonce = counter_nonce(42);
        let aad = 42u64.to_le_bytes();
        let plaintext = b"test data";

        let ciphertext = encrypt_section(plaintext, &dek, &nonce, &aad).expect("encrypt");

        let wrong_aad = 99u64.to_le_bytes();
        let result = decrypt_section(&ciphertext, &dek, &nonce, &wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_section_with_wrong_dek_fails() {
        let dek1 = generate_dek().expect("dek1");
        let dek2 = generate_dek().expect("dek2");
        let nonce = counter_nonce(42);
        let aad = 42u64.to_le_bytes();
        let plaintext = b"test data";

        let ciphertext = encrypt_section(plaintext, &dek1, &nonce, &aad).expect("encrypt");

        let result = decrypt_section(&ciphertext, &dek2, &nonce, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_section_with_wrong_nonce_fails() {
        let dek = generate_dek().expect("dek");
        let nonce1 = counter_nonce(42);
        let nonce2 = counter_nonce(99);
        let aad = 42u64.to_le_bytes();
        let plaintext = b"test data";

        let ciphertext = encrypt_section(plaintext, &dek, &nonce1, &aad).expect("encrypt");

        let result = decrypt_section(&ciphertext, &dek, &nonce2, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn rewrap_header_round_trip() {
        let dek = generate_dek().expect("dek");
        let old_kek = generate_kek().expect("old kek");
        let new_kek = generate_kek().expect("new kek");
        let old_kek_id = [0x01u8; KEK_ID_SIZE];
        let new_kek_id = [0x02u8; KEK_ID_SIZE];

        let old_header = wrap_dek(&dek, &old_kek, old_kek_id).expect("wrap old");
        let new_header =
            rewrap_header(&old_header, &old_kek, &new_kek, new_kek_id).expect("rewrap");

        assert_eq!(new_header.kek_id, new_kek_id);

        let unwrapped = unwrap_dek(&new_header, &new_kek).expect("unwrap new");
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
        assert_eq!(new_header.kek_id, new_kek_id);
    }

    #[test]
    fn encrypt_and_decrypt_kek_round_trip() {
        let kek = generate_kek().expect("kek");
        let host_key = generate_host_key().expect("host key");
        let kek_id = [0x42u8; KEK_ID_SIZE];

        let encrypted = encrypt_kek(&kek, &host_key, kek_id).expect("encrypt");
        let decrypted = decrypt_kek(&encrypted, &host_key, kek_id).expect("decrypt");

        assert_eq!(decrypted.as_bytes(), kek.as_bytes());
    }

    #[test]
    fn decrypt_kek_with_wrong_host_key_fails() {
        let kek = generate_kek().expect("kek");
        let host_key1 = generate_host_key().expect("host key 1");
        let host_key2 = generate_host_key().expect("host key 2");
        let kek_id = [0x42u8; KEK_ID_SIZE];

        let encrypted = encrypt_kek(&kek, &host_key1, kek_id).expect("encrypt");
        let result = decrypt_kek(&encrypted, &host_key2, kek_id);

        assert!(result.is_err());
    }

    #[test]
    fn decrypt_kek_with_wrong_kek_id_fails() {
        let kek = generate_kek().expect("kek");
        let host_key = generate_host_key().expect("host key");
        let kek_id1 = [0x42u8; KEK_ID_SIZE];
        let kek_id2 = [0x99u8; KEK_ID_SIZE];

        let encrypted = encrypt_kek(&kek, &host_key, kek_id1).expect("encrypt");
        let result = decrypt_kek(&encrypted, &host_key, kek_id2);

        assert!(result.is_err());
    }

    #[test]
    fn encryption_header_serialization_round_trip() {
        let dek = generate_dek().expect("dek");
        let kek = generate_kek().expect("kek");
        let kek_id = [0xCCu8; KEK_ID_SIZE];

        let header = wrap_dek(&dek, &kek, kek_id).expect("wrap");
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), ENCRYPTION_HEADER_SIZE);

        let parsed = EncryptionHeader::from_bytes(&bytes);
        assert_eq!(parsed.kek_id, header.kek_id);
        assert_eq!(parsed.wrapped_dek, header.wrapped_dek);
        assert_eq!(parsed.nonce, header.nonce);
    }

    #[test]
    fn counter_nonce_produces_unique_values() {
        let n1 = counter_nonce(0);
        let n2 = counter_nonce(1);
        let n3 = counter_nonce(u64::MAX);

        assert_ne!(n1, n2);
        assert_ne!(n2, n3);

        // Verify deterministic
        assert_eq!(n1, counter_nonce(0));
    }

    #[test]
    fn distinct_deks_produce_different_ciphertexts() {
        let dek1 = generate_dek().expect("dek1");
        let dek2 = generate_dek().expect("dek2");
        let nonce = counter_nonce(1);
        let aad = 1u64.to_le_bytes();
        let plaintext = b"identical plaintext";

        let ct1 = encrypt_section(plaintext, &dek1, &nonce, &aad).expect("encrypt1");
        let ct2 = encrypt_section(plaintext, &dek2, &nonce, &aad).expect("encrypt2");

        assert_ne!(ct1, ct2);
    }

    // --- Property tests ---

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn proptest_encrypt_decrypt_round_trip(
            plaintext in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            let dek = generate_dek().expect("dek");
            let nonce = counter_nonce(42);
            let aad = 42u64.to_le_bytes();

            let ct = encrypt_section(&plaintext, &dek, &nonce, &aad).expect("encrypt");
            prop_assert_eq!(ct.len(), plaintext.len() + TAG_SIZE);

            let decrypted = decrypt_section(&ct, &dek, &nonce, &aad).expect("decrypt");
            prop_assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn proptest_tampered_ciphertext_fails(
            plaintext in prop::collection::vec(any::<u8>(), 1..256)
        ) {
            let dek = generate_dek().expect("dek");
            let nonce = counter_nonce(7);
            let aad = 7u64.to_le_bytes();

            let ct = encrypt_section(&plaintext, &dek, &nonce, &aad).expect("encrypt");

            // Tamper: flip last byte of ciphertext (in the GCM tag)
            let mut tampered = ct;
            let last = tampered.len() - 1;
            tampered[last] ^= 0xFF;

            let result = decrypt_section(&tampered, &dek, &nonce, &aad);
            prop_assert!(result.is_err(), "tampering must fail GCM auth");
        }

        #[test]
        fn proptest_wrong_key_fails(
            plaintext in prop::collection::vec(any::<u8>(), 1..256)
        ) {
            let dek1 = generate_dek().expect("dek1");
            let dek2 = generate_dek().expect("dek2");
            let nonce = counter_nonce(1);
            let aad = 1u64.to_le_bytes();

            let ct = encrypt_section(&plaintext, &dek1, &nonce, &aad).expect("encrypt");
            let result = decrypt_section(&ct, &dek2, &nonce, &aad);
            prop_assert!(result.is_err(), "wrong key must fail decryption");
        }
    }
}
