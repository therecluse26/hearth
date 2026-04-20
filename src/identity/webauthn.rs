//! `WebAuthn` / Passkeys implementation (FIDO2).
//!
//! Provides `WebAuthn` registration and authentication ceremonies with
//! multi-credential and discoverable credential (resident key) support.
//! Uses `ciborium` for CBOR/COSE parsing and `ring` for
//! ES256 (P-256) and `EdDSA` (Ed25519) signature verification.
//!
//! Attestation: supports "none" and "packed" self-attestation.
//! TPM/x5c attestation returns an error (would require X.509 chain validation).

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SecureRandom;
use ring::signature;
use serde::{Deserialize, Serialize};

use crate::core::UserId;
use crate::identity::error::IdentityError;

/// `WebAuthn` challenge size in bytes (minimum 16 per spec, we use 32).
const CHALLENGE_SIZE: usize = 32;

/// Maximum age of a pending challenge before expiry (5 minutes in microseconds).
const CHALLENGE_EXPIRY_MICROS: i64 = 5 * 60 * 1_000_000;

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256 on P-256).
const COSE_ALG_ES256: i64 = -7;

/// COSE algorithm identifier for `EdDSA`.
const COSE_ALG_EDDSA: i64 = -8;

/// COSE key type for EC2 (Elliptic Curve, 2-coordinate).
const COSE_KTY_EC2: i64 = 2;

/// COSE key type for OKP (Octet Key Pair — Ed25519).
const COSE_KTY_OKP: i64 = 1;

/// COSE EC2 curve identifier for P-256.
const COSE_CRV_P256: i64 = 1;

/// COSE OKP curve identifier for Ed25519.
const COSE_CRV_ED25519: i64 = 6;

// COSE key parameter labels (from RFC 9052 / RFC 9053)
/// Key type parameter.
const COSE_LABEL_KTY: i64 = 1;
/// Algorithm parameter.
const COSE_LABEL_ALG: i64 = 3;
/// EC2/OKP curve parameter.
const COSE_LABEL_CRV: i64 = -1;
/// EC2 x-coordinate / OKP public key.
const COSE_LABEL_X: i64 = -2;
/// EC2 y-coordinate.
const COSE_LABEL_Y: i64 = -3;

/// A pending `WebAuthn` challenge awaiting completion.
#[derive(Debug, Clone)]
pub(crate) struct PendingWebAuthnChallenge {
    /// The raw challenge bytes (32 bytes, base64url-encoded for the client).
    pub challenge: Vec<u8>,
    /// The relying party ID (e.g., "example.com").
    pub rp_id: String,
    /// The user ID this challenge is for (None for discoverable auth).
    pub user_id: Option<UserId>,
    /// Whether this is a registration or authentication challenge.
    #[allow(dead_code)]
    pub ceremony_type: CeremonyType,
    /// When this challenge was created (Unix microseconds).
    pub created_at: i64,
}

/// Type of `WebAuthn` ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CeremonyType {
    /// Registration (credential creation).
    Registration,
    /// Authentication (assertion).
    Authentication,
}

/// Information returned to the caller after successful registration.
#[derive(Debug, Clone)]
pub struct WebAuthnCredentialInfo {
    /// The credential ID (opaque bytes, base64url-encoded for storage/transport).
    pub(crate) credential_id: Vec<u8>,
    /// The COSE algorithm used by this credential.
    pub(crate) algorithm: i64,
    /// Whether the credential is discoverable (resident key).
    pub(crate) discoverable: bool,
}

impl WebAuthnCredentialInfo {
    /// Returns the raw credential ID bytes.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Returns the credential ID as a base64url string.
    pub fn credential_id_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }

    /// Returns the COSE algorithm identifier.
    pub fn algorithm(&self) -> i64 {
        self.algorithm
    }

    /// Returns whether this is a discoverable (resident key) credential.
    pub fn discoverable(&self) -> bool {
        self.discoverable
    }
}

/// A stored `WebAuthn` credential (persisted in storage engine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredWebAuthnCredential {
    /// Credential ID bytes (base64url-encoded for JSON serialization).
    pub credential_id_b64: String,
    /// COSE-encoded public key bytes (base64url-encoded).
    pub cose_public_key_b64: String,
    /// COSE algorithm identifier (e.g., -7 for ES256).
    pub algorithm: i64,
    /// Authenticator's signature counter.
    pub sign_count: u32,
    /// Whether this credential is discoverable (resident key).
    pub discoverable: bool,
    /// The relying party ID used during registration.
    pub rp_id: String,
    /// When this credential was registered (Unix microseconds).
    pub created_at: i64,
}

/// Options for starting a `WebAuthn` registration ceremony.
#[derive(Debug, Clone)]
pub struct RegistrationOptions {
    /// The relying party ID (typically the domain, e.g., "example.com").
    pub rp_id: String,
    /// Whether to request a discoverable (resident key) credential.
    pub discoverable: bool,
}

/// Options for starting a `WebAuthn` authentication ceremony.
#[derive(Debug, Clone)]
pub struct AuthenticationOptions {
    /// The relying party ID (must match the one used during registration).
    pub rp_id: String,
}

/// Parameters for completing a `WebAuthn` authentication ceremony.
#[derive(Debug)]
pub struct CompleteAuthenticationParams<'a> {
    /// The credential ID being authenticated.
    pub credential_id: &'a [u8],
    /// The raw `clientDataJSON` from the authenticator.
    pub client_data_json: &'a [u8],
    /// The raw authenticator data bytes.
    pub authenticator_data: &'a [u8],
    /// The signature bytes from the authenticator.
    pub signature: &'a [u8],
    /// Optional user handle (for discoverable credentials).
    pub user_handle: Option<&'a [u8]>,
    /// The expected origin (e.g., "<https://example.com>").
    pub origin: &'a str,
}

/// Result of a successful `WebAuthn` authentication.
#[derive(Debug, Clone)]
pub struct WebAuthnAuthResult {
    /// The credential ID that was used.
    credential_id: Vec<u8>,
    /// The user ID that owns this credential.
    user_id: UserId,
    /// The updated sign counter.
    sign_count: u32,
}

impl WebAuthnAuthResult {
    /// Returns the credential ID used for authentication.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Returns the authenticated user's ID.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the updated signature counter.
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }
}

/// In-memory store for pending `WebAuthn` challenges.
///
/// Challenges are keyed by base64url-encoded challenge bytes and expire
/// after `CHALLENGE_EXPIRY_MICROS`. Cleanup happens lazily at ceremony start.
pub(crate) struct WebAuthnChallengeStore {
    challenges: Mutex<HashMap<String, PendingWebAuthnChallenge>>,
}

impl fmt::Debug for WebAuthnChallengeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebAuthnChallengeStore")
            .finish_non_exhaustive()
    }
}

impl WebAuthnChallengeStore {
    /// Creates a new empty challenge store.
    pub(crate) fn new() -> Self {
        Self {
            challenges: Mutex::new(HashMap::new()),
        }
    }

    /// Inserts a pending challenge. Returns the base64url-encoded challenge.
    pub(crate) fn insert(&self, challenge: PendingWebAuthnChallenge) -> String {
        let key = URL_SAFE_NO_PAD.encode(&challenge.challenge);
        let mut map = self.challenges.lock().expect("challenge store lock");
        map.insert(key.clone(), challenge);
        key
    }

    /// Removes and returns a pending challenge by its base64url key.
    ///
    /// Returns `None` if the challenge does not exist.
    pub(crate) fn remove(&self, key: &str) -> Option<PendingWebAuthnChallenge> {
        let mut map = self.challenges.lock().expect("challenge store lock");
        map.remove(key)
    }

    /// Removes expired challenges from the store.
    pub(crate) fn cleanup_expired(&self, now_micros: i64) {
        let mut map = self.challenges.lock().expect("challenge store lock");
        map.retain(|_, v| (now_micros - v.created_at) < CHALLENGE_EXPIRY_MICROS);
    }
}

/// Generates a cryptographically random `WebAuthn` challenge.
pub(crate) fn generate_challenge() -> Result<Vec<u8>, IdentityError> {
    let rng = ring::rand::SystemRandom::new();
    let mut buf = vec![0u8; CHALLENGE_SIZE];
    rng.fill(&mut buf)
        .map_err(|_| IdentityError::SigningError {
            reason: "failed to generate WebAuthn challenge".to_string(),
        })?;
    Ok(buf)
}

/// Parsed `clientDataJSON` fields relevant to `WebAuthn` ceremonies.
#[derive(Debug)]
struct ClientData {
    /// `webauthn.create` or `webauthn.get`
    r#type: String,
    /// Base64url-encoded challenge.
    challenge: String,
    /// The origin (e.g., `https://example.com`).
    origin: String,
}

/// Parses the `clientDataJSON` from a `WebAuthn` response.
fn parse_client_data_json(raw: &[u8]) -> Result<ClientData, IdentityError> {
    #[derive(Deserialize)]
    struct RawClientData {
        #[serde(rename = "type")]
        r#type: String,
        challenge: String,
        origin: String,
    }

    let parsed: RawClientData =
        serde_json::from_slice(raw).map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid clientDataJSON: {e}"),
        })?;

    Ok(ClientData {
        r#type: parsed.r#type,
        challenge: parsed.challenge,
        origin: parsed.origin,
    })
}

/// Parsed authenticator data from a `WebAuthn` response.
#[derive(Debug)]
struct AuthenticatorData {
    /// SHA-256 hash of the RP ID (32 bytes).
    rp_id_hash: [u8; 32],
    /// Flags byte.
    flags: u8,
    /// Signature counter (big-endian u32).
    sign_count: u32,
    /// Attested credential data (present in registration only).
    attested_credential: Option<AttestedCredentialData>,
}

/// Attested credential data from the authenticator.
#[derive(Debug)]
struct AttestedCredentialData {
    /// AAGUID of the authenticator (16 bytes).
    _aaguid: [u8; 16],
    /// The credential ID bytes.
    credential_id: Vec<u8>,
    /// The COSE-encoded public key bytes.
    cose_public_key: Vec<u8>,
}

/// Parses the raw authenticator data bytes.
///
/// Layout (per `WebAuthn` spec section 6.1):
///
/// - Bytes 0..32: `rpIdHash` (SHA-256 of RP ID)
/// - Byte 32: flags
/// - Bytes 33..37: `signCount` (big-endian u32)
/// - Bytes 37..: `attestedCredentialData` (if AT flag set)
fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData, IdentityError> {
    if data.len() < 37 {
        return Err(IdentityError::InvalidInput {
            reason: format!(
                "authenticator data too short: {} bytes, need at least 37",
                data.len()
            ),
        });
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[..32]);

    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    // AT flag (bit 6) indicates attested credential data is present
    let attested_credential = if flags & 0x40 != 0 {
        if data.len() < 55 {
            return Err(IdentityError::InvalidInput {
                reason: "authenticator data too short for attested credential data".to_string(),
            });
        }

        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&data[37..53]);

        let cred_id_len = u16::from_be_bytes([data[53], data[54]]) as usize;
        let cred_id_end = 55 + cred_id_len;

        if data.len() < cred_id_end {
            return Err(IdentityError::InvalidInput {
                reason: "authenticator data truncated in credential ID".to_string(),
            });
        }

        let credential_id = data[55..cred_id_end].to_vec();

        // The rest is the COSE public key (CBOR-encoded)
        let cose_public_key = data[cred_id_end..].to_vec();

        Some(AttestedCredentialData {
            _aaguid: aaguid,
            credential_id,
            cose_public_key,
        })
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential,
    })
}

/// Parsed attestation object from a registration response.
#[derive(Debug)]
struct AttestationObject {
    /// Raw authenticator data bytes.
    auth_data: Vec<u8>,
    /// Attestation statement (format-specific).
    att_stmt: AttestationStatement,
}

/// Attestation statement variants.
#[derive(Debug)]
enum AttestationStatement {
    /// "none" format — no attestation.
    None,
    /// "packed" self-attestation — sig + alg, no x5c.
    PackedSelf {
        /// COSE algorithm identifier.
        alg: i64,
        /// Signature bytes.
        sig: Vec<u8>,
    },
    /// "packed" with x5c certificate chain — unsupported.
    PackedFull,
    /// Unsupported attestation format.
    Unsupported(String),
}

/// Parses a CBOR-encoded attestation object.
fn parse_attestation_object(raw: &[u8]) -> Result<AttestationObject, IdentityError> {
    let value: ciborium::Value =
        ciborium::from_reader(raw).map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid CBOR in attestation object: {e}"),
        })?;

    let map = value.as_map().ok_or_else(|| IdentityError::InvalidInput {
        reason: "attestation object is not a CBOR map".to_string(),
    })?;

    let mut fmt = None;
    let mut auth_data = None;
    let mut att_stmt_value = None;

    for (k, v) in map {
        let key = k.as_text().unwrap_or("");
        match key {
            "fmt" => {
                fmt = v.as_text().map(std::string::ToString::to_string);
            }
            "authData" => {
                auth_data = v.as_bytes().cloned();
            }
            "attStmt" => {
                att_stmt_value = Some(v.clone());
            }
            _ => {}
        }
    }

    let fmt = fmt.ok_or_else(|| IdentityError::InvalidInput {
        reason: "missing 'fmt' in attestation object".to_string(),
    })?;

    let auth_data = auth_data.ok_or_else(|| IdentityError::InvalidInput {
        reason: "missing 'authData' in attestation object".to_string(),
    })?;

    let att_stmt = match fmt.as_str() {
        "none" => AttestationStatement::None,
        "packed" => parse_packed_att_stmt(att_stmt_value.as_ref())?,
        other => AttestationStatement::Unsupported(other.to_string()),
    };

    Ok(AttestationObject {
        auth_data,
        att_stmt,
    })
}

/// Parses a "packed" attestation statement.
fn parse_packed_att_stmt(
    value: Option<&ciborium::Value>,
) -> Result<AttestationStatement, IdentityError> {
    let map = value
        .and_then(|v| v.as_map())
        .ok_or_else(|| IdentityError::InvalidInput {
            reason: "missing or invalid attStmt in packed attestation".to_string(),
        })?;

    let mut alg = None;
    let mut sig = None;
    let mut has_x5c = false;

    for (k, v) in map {
        let key = k.as_text().unwrap_or("");
        match key {
            "alg" => {
                alg = v.as_integer().and_then(|i| i64::try_from(i).ok());
            }
            "sig" => {
                sig = v.as_bytes().cloned();
            }
            "x5c" => {
                has_x5c = true;
            }
            _ => {}
        }
    }

    if has_x5c {
        return Ok(AttestationStatement::PackedFull);
    }

    let alg = alg.ok_or_else(|| IdentityError::InvalidInput {
        reason: "missing 'alg' in packed attStmt".to_string(),
    })?;

    let sig = sig.ok_or_else(|| IdentityError::InvalidInput {
        reason: "missing 'sig' in packed attStmt".to_string(),
    })?;

    Ok(AttestationStatement::PackedSelf { alg, sig })
}

/// Extracts the COSE algorithm and raw public key parameters from COSE key bytes.
fn extract_cose_key_params(cose_bytes: &[u8]) -> Result<(i64, i64, i64), IdentityError> {
    let value: ciborium::Value =
        ciborium::from_reader(cose_bytes).map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid CBOR in COSE key: {e}"),
        })?;

    let map = value.as_map().ok_or_else(|| IdentityError::InvalidInput {
        reason: "COSE key is not a CBOR map".to_string(),
    })?;

    let mut kty = None;
    let mut alg = None;
    let mut crv = None;

    for (k, v) in map {
        if let Some(label) = k.as_integer().and_then(|i| i64::try_from(i).ok()) {
            match label {
                COSE_LABEL_KTY => kty = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                COSE_LABEL_ALG => alg = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                COSE_LABEL_CRV => crv = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                _ => {}
            }
        }
    }

    let kty = kty.ok_or_else(|| IdentityError::InvalidInput {
        reason: "missing kty in COSE key".to_string(),
    })?;

    let alg = alg.ok_or_else(|| IdentityError::InvalidInput {
        reason: "missing alg in COSE key".to_string(),
    })?;

    let crv = crv.ok_or_else(|| IdentityError::InvalidInput {
        reason: "missing crv in COSE key".to_string(),
    })?;

    Ok((kty, alg, crv))
}

/// Extracts the raw public key bytes from a COSE key for use with `ring`.
///
/// For ES256 (EC2/P-256): returns the uncompressed point (0x04 || x || y), 65 bytes.
/// For `EdDSA` (OKP/Ed25519): returns the 32-byte public key.
fn extract_public_key_bytes(cose_bytes: &[u8]) -> Result<(i64, Vec<u8>), IdentityError> {
    let value: ciborium::Value =
        ciborium::from_reader(cose_bytes).map_err(|e| IdentityError::InvalidInput {
            reason: format!("invalid CBOR in COSE key: {e}"),
        })?;

    let map = value.as_map().ok_or_else(|| IdentityError::InvalidInput {
        reason: "COSE key is not a CBOR map".to_string(),
    })?;

    let (kty, alg, crv) = extract_cose_key_params(cose_bytes)?;

    let mut x_bytes = None;
    let mut y_bytes = None;

    for (k, v) in map {
        if let Some(label) = k.as_integer().and_then(|i| i64::try_from(i).ok()) {
            match label {
                COSE_LABEL_X => x_bytes = v.as_bytes().cloned(),
                COSE_LABEL_Y => y_bytes = v.as_bytes().cloned(),
                _ => {}
            }
        }
    }

    match (kty, crv) {
        (COSE_KTY_EC2, COSE_CRV_P256) => {
            let x = x_bytes.ok_or_else(|| IdentityError::InvalidInput {
                reason: "missing x-coordinate in EC2 COSE key".to_string(),
            })?;
            let y = y_bytes.ok_or_else(|| IdentityError::InvalidInput {
                reason: "missing y-coordinate in EC2 COSE key".to_string(),
            })?;
            if x.len() != 32 || y.len() != 32 {
                return Err(IdentityError::InvalidInput {
                    reason: format!(
                        "invalid P-256 key coordinates: x={}, y={}",
                        x.len(),
                        y.len()
                    ),
                });
            }
            // Uncompressed point format: 0x04 || x || y
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(&x);
            uncompressed.extend_from_slice(&y);
            Ok((alg, uncompressed))
        }
        (COSE_KTY_OKP, COSE_CRV_ED25519) => {
            let x = x_bytes.ok_or_else(|| IdentityError::InvalidInput {
                reason: "missing x (public key) in OKP COSE key".to_string(),
            })?;
            if x.len() != 32 {
                return Err(IdentityError::InvalidInput {
                    reason: format!("invalid Ed25519 key length: {}", x.len()),
                });
            }
            Ok((alg, x))
        }
        _ => Err(IdentityError::InvalidInput {
            reason: format!("unsupported COSE key type: kty={kty}, crv={crv}"),
        }),
    }
}

/// Verifies a `WebAuthn` signature using the stored COSE public key.
///
/// `signed_data` is the data that was signed (`authData` || SHA-256(`clientDataJSON`)
/// for assertions, or the attestation-specific signed data for registration).
fn verify_signature(
    cose_public_key: &[u8],
    signed_data: &[u8],
    signature_bytes: &[u8],
) -> Result<(), IdentityError> {
    let (alg, raw_key) = extract_public_key_bytes(cose_public_key)?;

    match alg {
        COSE_ALG_ES256 => {
            // Real authenticators (CTAP2 §6.5.6) produce DER/ASN.1-encoded
            // ECDSA signatures. Try ASN.1 first, then fall back to fixed
            // format for test/synthetic authenticators.
            let asn1_key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &raw_key);
            asn1_key
                .verify(signed_data, signature_bytes)
                .or_else(|_| {
                    let fixed_key = signature::UnparsedPublicKey::new(
                        &signature::ECDSA_P256_SHA256_FIXED,
                        &raw_key,
                    );
                    fixed_key.verify(signed_data, signature_bytes)
                })
                .map_err(|_| IdentityError::InvalidInput {
                    reason: "ES256 signature verification failed".to_string(),
                })
        }
        COSE_ALG_EDDSA => {
            let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &raw_key);
            public_key
                .verify(signed_data, signature_bytes)
                .map_err(|_| IdentityError::InvalidInput {
                    reason: "EdDSA signature verification failed".to_string(),
                })
        }
        _ => Err(IdentityError::InvalidInput {
            reason: format!("unsupported COSE algorithm: {alg}"),
        }),
    }
}

/// Parses arbitrary bytes through the `WebAuthn` CBOR/authenticator-data pipeline.
///
/// Intended for fuzz testing: feeds `data` to both `parse_attestation_object`
/// and `parse_authenticator_data`. Must never panic — always returns `Ok` or `Err`.
pub fn fuzz_parse_webauthn(data: &[u8]) {
    // Exercise attestation object parsing (CBOR → structure)
    let _ = parse_attestation_object(data);
    // Exercise authenticator data parsing (binary → structure)
    let _ = parse_authenticator_data(data);
    // Exercise clientDataJSON parsing (JSON → structure)
    let _ = parse_client_data_json(data);
    // Exercise COSE key extraction
    let _ = extract_cose_key_params(data);
    let _ = extract_public_key_bytes(data);
}

/// Completes a `WebAuthn` registration ceremony.
///
/// Validates the attestation response against the stored challenge, extracts
/// the credential public key, and returns the credential info + stored record.
pub(crate) fn complete_registration(
    pending: &PendingWebAuthnChallenge,
    client_data_json: &[u8],
    attestation_object_bytes: &[u8],
    origin: &str,
    now_micros: i64,
) -> Result<(WebAuthnCredentialInfo, StoredWebAuthnCredential), IdentityError> {
    // 1. Parse and validate clientDataJSON
    let client_data = parse_client_data_json(client_data_json)?;

    if client_data.r#type != "webauthn.create" {
        return Err(IdentityError::WebAuthnRegistrationFailed {
            reason: format!(
                "expected type 'webauthn.create', got '{}'",
                client_data.r#type
            ),
        });
    }

    // Verify challenge matches
    let expected_challenge = URL_SAFE_NO_PAD.encode(&pending.challenge);
    if client_data.challenge != expected_challenge {
        return Err(IdentityError::WebAuthnRegistrationFailed {
            reason: "challenge mismatch".to_string(),
        });
    }

    // Verify origin
    if client_data.origin != origin {
        return Err(IdentityError::WebAuthnRegistrationFailed {
            reason: format!(
                "origin mismatch: expected '{origin}', got '{}'",
                client_data.origin
            ),
        });
    }

    // 2. Parse attestation object
    let att_obj = parse_attestation_object(attestation_object_bytes)?;

    // 3. Parse authenticator data
    let auth_data = parse_authenticator_data(&att_obj.auth_data)?;

    // Verify RP ID hash
    let expected_rp_id_hash = ring::digest::digest(&ring::digest::SHA256, pending.rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash.as_ref() {
        return Err(IdentityError::WebAuthnRegistrationFailed {
            reason: "RP ID hash mismatch".to_string(),
        });
    }

    // Verify UP (User Present) flag is set
    if auth_data.flags & 0x01 == 0 {
        return Err(IdentityError::WebAuthnRegistrationFailed {
            reason: "user presence flag not set".to_string(),
        });
    }

    // 4. Extract attested credential data
    let cred_data =
        auth_data
            .attested_credential
            .ok_or_else(|| IdentityError::WebAuthnRegistrationFailed {
                reason: "no attested credential data in authenticator data".to_string(),
            })?;

    // 5. Validate the COSE public key is parseable and supported
    let (alg, _raw_key) = extract_public_key_bytes(&cred_data.cose_public_key)?;

    // 6. Validate attestation statement
    match &att_obj.att_stmt {
        AttestationStatement::None => {
            // No attestation — always accepted
        }
        AttestationStatement::PackedSelf { alg: stmt_alg, sig } => {
            // Self-attestation: verify signature over authData || clientDataHash
            // using the credential public key itself
            if *stmt_alg != alg {
                return Err(IdentityError::InvalidAttestation {
                    reason: format!(
                        "packed self-attestation alg mismatch: stmt={stmt_alg}, key={alg}"
                    ),
                });
            }
            let client_data_hash = ring::digest::digest(&ring::digest::SHA256, client_data_json);
            let mut signed_data = att_obj.auth_data.clone();
            signed_data.extend_from_slice(client_data_hash.as_ref());
            verify_signature(&cred_data.cose_public_key, &signed_data, sig)?;
        }
        AttestationStatement::PackedFull => {
            return Err(IdentityError::InvalidAttestation {
                reason: "packed attestation with x5c certificate chain is not supported"
                    .to_string(),
            });
        }
        AttestationStatement::Unsupported(fmt) => {
            return Err(IdentityError::InvalidAttestation {
                reason: format!("unsupported attestation format: {fmt}"),
            });
        }
    }

    // 7. Build credential info and stored record
    // Discoverable is set by the caller's request in the engine layer,
    // not derived from flags. Default to false here; caller overrides.
    let credential_id = cred_data.credential_id;

    let info = WebAuthnCredentialInfo {
        credential_id: credential_id.clone(),
        algorithm: alg,
        discoverable: false, // Overridden by caller
    };

    let stored = StoredWebAuthnCredential {
        credential_id_b64: URL_SAFE_NO_PAD.encode(&credential_id),
        cose_public_key_b64: URL_SAFE_NO_PAD.encode(&cred_data.cose_public_key),
        algorithm: alg,
        sign_count: auth_data.sign_count,
        discoverable: false, // Overridden by caller
        rp_id: pending.rp_id.clone(),
        created_at: now_micros,
    };

    Ok((info, stored))
}

/// Completes a `WebAuthn` authentication ceremony.
///
/// Validates the assertion response, verifies the signature against the
/// stored credential, checks the sign counter, and returns the result.
pub(crate) fn complete_authentication(
    pending: &PendingWebAuthnChallenge,
    stored: &StoredWebAuthnCredential,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature_bytes: &[u8],
    user_handle: Option<&[u8]>,
    origin: &str,
) -> Result<WebAuthnAuthResult, IdentityError> {
    // 1. Parse and validate clientDataJSON
    let client_data = parse_client_data_json(client_data_json)?;

    if client_data.r#type != "webauthn.get" {
        return Err(IdentityError::WebAuthnAuthenticationFailed {
            reason: format!("expected type 'webauthn.get', got '{}'", client_data.r#type),
        });
    }

    // Verify challenge
    let expected_challenge = URL_SAFE_NO_PAD.encode(&pending.challenge);
    if client_data.challenge != expected_challenge {
        return Err(IdentityError::InvalidAssertion {
            reason: "challenge mismatch".to_string(),
        });
    }

    // Verify origin
    if client_data.origin != origin {
        return Err(IdentityError::InvalidAssertion {
            reason: format!(
                "origin mismatch: expected '{origin}', got '{}'",
                client_data.origin
            ),
        });
    }

    // 2. Parse authenticator data
    let auth_data = parse_authenticator_data(authenticator_data)?;

    // Verify RP ID hash
    let expected_rp_id_hash = ring::digest::digest(&ring::digest::SHA256, pending.rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash.as_ref() {
        return Err(IdentityError::InvalidAssertion {
            reason: "RP ID hash mismatch".to_string(),
        });
    }

    // Verify UP flag
    if auth_data.flags & 0x01 == 0 {
        return Err(IdentityError::InvalidAssertion {
            reason: "user presence flag not set".to_string(),
        });
    }

    // 3. Check sign counter (cloned authenticator detection)
    // If the authenticator reports a non-zero counter, it must be strictly
    // greater than the stored counter.
    if (auth_data.sign_count != 0 || stored.sign_count != 0)
        && auth_data.sign_count <= stored.sign_count
    {
        return Err(IdentityError::InvalidAssertion {
            reason: format!(
                "sign counter did not increment: stored={}, received={}",
                stored.sign_count, auth_data.sign_count
            ),
        });
    }

    // 4. Verify signature: sig = sign(authData || SHA-256(clientDataJSON))
    let cose_key_bytes = URL_SAFE_NO_PAD
        .decode(&stored.cose_public_key_b64)
        .map_err(|e| IdentityError::InvalidAssertion {
            reason: format!("invalid stored COSE key: {e}"),
        })?;

    let client_data_hash = ring::digest::digest(&ring::digest::SHA256, client_data_json);
    let mut signed_data = authenticator_data.to_vec();
    signed_data.extend_from_slice(client_data_hash.as_ref());

    verify_signature(&cose_key_bytes, &signed_data, signature_bytes).map_err(|_| {
        IdentityError::InvalidAssertion {
            reason: "signature verification failed".to_string(),
        }
    })?;

    // 5. Resolve user ID
    let user_id = if let Some(uid) = pending.user_id.as_ref() {
        uid.clone()
    } else if let Some(handle) = user_handle {
        // Discoverable credential: userHandle contains the user UUID,
        // either as raw 16 bytes or as a UTF-8 UUID string.
        let uuid = if handle.len() == 16 {
            uuid::Uuid::from_slice(handle).map_err(|_| IdentityError::InvalidAssertion {
                reason: "invalid 16-byte userHandle".to_string(),
            })?
        } else {
            let uuid_str =
                std::str::from_utf8(handle).map_err(|_| IdentityError::InvalidAssertion {
                    reason: "invalid userHandle encoding".to_string(),
                })?;
            uuid::Uuid::parse_str(uuid_str).map_err(|_| IdentityError::InvalidAssertion {
                reason: "invalid user UUID in userHandle".to_string(),
            })?
        };
        UserId::new(uuid)
    } else {
        return Err(IdentityError::InvalidAssertion {
            reason: "no user ID available (not discoverable and no user specified)".to_string(),
        });
    };

    let credential_id = URL_SAFE_NO_PAD
        .decode(&stored.credential_id_b64)
        .map_err(|e| IdentityError::InvalidAssertion {
            reason: format!("invalid stored credential ID: {e}"),
        })?;

    Ok(WebAuthnAuthResult {
        credential_id,
        user_id,
        sign_count: auth_data.sign_count,
    })
}

// ============================================================================
// Test helper — builds bit-accurate mock authenticator responses
// ============================================================================

#[cfg(test)]
pub(crate) mod test_helper {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    /// Builds mock `WebAuthn` authenticator responses for testing.
    #[allow(dead_code)]
    pub(crate) struct WebAuthnTestHelper {
        /// The P-256 key pair (PKCS#8 DER).
        key_pair_pkcs8: Vec<u8>,
        /// The credential ID (random bytes).
        pub credential_id: Vec<u8>,
        /// The relying party ID.
        pub rp_id: String,
    }

    #[allow(dead_code)]
    impl WebAuthnTestHelper {
        /// Creates a new test helper with a fresh P-256 key pair.
        pub fn new(rp_id: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate P-256 key");

            let mut cred_id = vec![0u8; 32];
            rng.fill(&mut cred_id).expect("random cred id");

            Self {
                key_pair_pkcs8: pkcs8.as_ref().to_vec(),
                credential_id: cred_id,
                rp_id: rp_id.to_string(),
            }
        }

        /// Returns the COSE-encoded public key (EC2/P-256/ES256).
        pub fn cose_public_key(&self) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");

            let pub_key = key_pair.public_key().as_ref();
            // pub_key is uncompressed point: 0x04 || x (32) || y (32)
            assert_eq!(pub_key.len(), 65);
            let x = &pub_key[1..33];
            let y = &pub_key[33..65];

            // Build COSE key as CBOR map
            let cose_map = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Integer(COSE_LABEL_KTY.into()),
                    ciborium::Value::Integer(COSE_KTY_EC2.into()),
                ),
                (
                    ciborium::Value::Integer(COSE_LABEL_ALG.into()),
                    ciborium::Value::Integer(COSE_ALG_ES256.into()),
                ),
                (
                    ciborium::Value::Integer(COSE_LABEL_CRV.into()),
                    ciborium::Value::Integer(COSE_CRV_P256.into()),
                ),
                (
                    ciborium::Value::Integer(COSE_LABEL_X.into()),
                    ciborium::Value::Bytes(x.to_vec()),
                ),
                (
                    ciborium::Value::Integer(COSE_LABEL_Y.into()),
                    ciborium::Value::Bytes(y.to_vec()),
                ),
            ]);

            let mut buf = Vec::new();
            ciborium::into_writer(&cose_map, &mut buf).expect("encode COSE key");
            buf
        }

        /// Builds authenticator data bytes.
        #[allow(clippy::cast_possible_truncation)] // credential IDs are always < u16::MAX
        pub fn build_auth_data(&self, sign_count: u32, include_credential: bool) -> Vec<u8> {
            let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, self.rp_id.as_bytes());
            let mut data = Vec::new();
            data.extend_from_slice(rp_id_hash.as_ref()); // 32 bytes

            // Flags: UP (0x01) | AT (0x40) if credential included
            let flags: u8 = if include_credential { 0x41 } else { 0x01 };
            data.push(flags);

            data.extend_from_slice(&sign_count.to_be_bytes()); // 4 bytes

            if include_credential {
                // AAGUID (16 zero bytes)
                data.extend_from_slice(&[0u8; 16]);
                // Credential ID length (big-endian u16)
                let cred_id_len = self.credential_id.len() as u16;
                data.extend_from_slice(&cred_id_len.to_be_bytes());
                // Credential ID
                data.extend_from_slice(&self.credential_id);
                // COSE public key
                data.extend_from_slice(&self.cose_public_key());
            }

            data
        }

        /// Builds a `clientDataJSON` for the given ceremony type.
        pub fn build_client_data_json(
            ceremony_type: &str,
            challenge: &[u8],
            origin: &str,
        ) -> Vec<u8> {
            let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
            serde_json::to_vec(&serde_json::json!({
                "type": ceremony_type,
                "challenge": challenge_b64,
                "origin": origin,
            }))
            .expect("serialize clientDataJSON")
        }

        /// Builds a registration response (attestation object + `clientDataJSON`).
        ///
        /// Returns `(client_data_json, attestation_object_bytes)`.
        pub fn build_registration_response(
            &self,
            challenge: &[u8],
            origin: &str,
        ) -> (Vec<u8>, Vec<u8>) {
            let client_data_json =
                Self::build_client_data_json("webauthn.create", challenge, origin);
            let auth_data = self.build_auth_data(0, true);

            // Attestation object: { fmt: "none", attStmt: {}, authData: bytes }
            let att_obj = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fmt".to_string()),
                    ciborium::Value::Text("none".to_string()),
                ),
                (
                    ciborium::Value::Text("attStmt".to_string()),
                    ciborium::Value::Map(vec![]),
                ),
                (
                    ciborium::Value::Text("authData".to_string()),
                    ciborium::Value::Bytes(auth_data),
                ),
            ]);

            let mut att_bytes = Vec::new();
            ciborium::into_writer(&att_obj, &mut att_bytes).expect("encode attestation");

            (client_data_json, att_bytes)
        }

        /// Builds a registration response with "packed" self-attestation.
        ///
        /// Returns `(client_data_json, attestation_object_bytes)`.
        pub fn build_packed_registration_response(
            &self,
            challenge: &[u8],
            origin: &str,
        ) -> (Vec<u8>, Vec<u8>) {
            let client_data_json =
                Self::build_client_data_json("webauthn.create", challenge, origin);
            let auth_data = self.build_auth_data(0, true);

            // Sign: authData || SHA-256(clientDataJSON)
            let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &client_data_json);
            let mut signed_data = auth_data.clone();
            signed_data.extend_from_slice(client_data_hash.as_ref());

            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair for signing");
            let sig = key_pair.sign(&rng, &signed_data).expect("sign");

            let att_obj = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fmt".to_string()),
                    ciborium::Value::Text("packed".to_string()),
                ),
                (
                    ciborium::Value::Text("attStmt".to_string()),
                    ciborium::Value::Map(vec![
                        (
                            ciborium::Value::Text("alg".to_string()),
                            ciborium::Value::Integer(COSE_ALG_ES256.into()),
                        ),
                        (
                            ciborium::Value::Text("sig".to_string()),
                            ciborium::Value::Bytes(sig.as_ref().to_vec()),
                        ),
                    ]),
                ),
                (
                    ciborium::Value::Text("authData".to_string()),
                    ciborium::Value::Bytes(auth_data),
                ),
            ]);

            let mut att_bytes = Vec::new();
            ciborium::into_writer(&att_obj, &mut att_bytes).expect("encode attestation");

            (client_data_json, att_bytes)
        }

        /// Builds an authentication response (assertion).
        ///
        /// Returns `(client_data_json, authenticator_data, signature, user_handle)`.
        pub fn build_authentication_response(
            &self,
            challenge: &[u8],
            origin: &str,
            sign_count: u32,
            user_handle: Option<&str>,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
            let client_data_json = Self::build_client_data_json("webauthn.get", challenge, origin);
            let auth_data = self.build_auth_data(sign_count, false);

            // Sign: authData || SHA-256(clientDataJSON)
            let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &client_data_json);
            let mut signed_data = auth_data.clone();
            signed_data.extend_from_slice(client_data_hash.as_ref());

            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            let sig = key_pair.sign(&rng, &signed_data).expect("sign");

            let handle = user_handle.map(|h| h.as_bytes().to_vec());

            (client_data_json, auth_data, sig.as_ref().to_vec(), handle)
        }

        /// Builds authenticator data with a custom RP ID (for RP ID mismatch tests).
        pub fn build_auth_data_custom_rp(rp_id: &str, sign_count: u32) -> Vec<u8> {
            let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, rp_id.as_bytes());
            let mut data = Vec::new();
            data.extend_from_slice(rp_id_hash.as_ref());
            data.push(0x01); // UP flag
            data.extend_from_slice(&sign_count.to_be_bytes());
            data
        }

        /// Signs arbitrary data with this helper's key pair.
        pub fn sign(&self, data: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            let sig = key_pair.sign(&rng, data).expect("sign");
            sig.as_ref().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helper::WebAuthnTestHelper;
    use super::*;

    #[test]
    fn challenge_generation_produces_32_bytes() {
        let challenge = generate_challenge().expect("generate");
        assert_eq!(challenge.len(), CHALLENGE_SIZE);
    }

    #[test]
    fn challenge_store_insert_and_remove() {
        let store = WebAuthnChallengeStore::new();
        let challenge = generate_challenge().expect("generate");
        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(UserId::generate()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };

        let key = store.insert(pending);
        assert!(store.remove(&key).is_some());
        assert!(store.remove(&key).is_none()); // Already removed
    }

    #[test]
    fn challenge_store_cleanup_expired() {
        let store = WebAuthnChallengeStore::new();
        let challenge = generate_challenge().expect("generate");
        let key = URL_SAFE_NO_PAD.encode(&challenge);
        let pending = PendingWebAuthnChallenge {
            challenge,
            rp_id: "example.com".to_string(),
            user_id: None,
            ceremony_type: CeremonyType::Authentication,
            created_at: 1_000_000,
        };

        store.insert(pending);
        // Cleanup at a time well past expiry
        store.cleanup_expired(1_000_000 + CHALLENGE_EXPIRY_MICROS + 1);
        assert!(store.remove(&key).is_none());
    }

    #[test]
    fn test_helper_produces_valid_cose_key() {
        let helper = WebAuthnTestHelper::new("example.com");
        let cose = helper.cose_public_key();
        // Should parse without error
        let (alg, raw) = extract_public_key_bytes(&cose).expect("parse COSE");
        assert_eq!(alg, COSE_ALG_ES256);
        assert_eq!(raw.len(), 65); // Uncompressed P-256 point
        assert_eq!(raw[0], 0x04);
    }

    #[test]
    fn parse_authenticator_data_too_short() {
        let result = parse_authenticator_data(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_client_data_json_valid() {
        let json = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.create",
            "challenge": "dGVzdA",
            "origin": "https://example.com",
        }))
        .expect("json");
        let cd = parse_client_data_json(&json).expect("parse");
        assert_eq!(cd.r#type, "webauthn.create");
        assert_eq!(cd.challenge, "dGVzdA");
        assert_eq!(cd.origin, "https://example.com");
    }

    #[test]
    fn parse_client_data_json_invalid() {
        let result = parse_client_data_json(b"not json");
        assert!(result.is_err());
    }

    // ====================================================================
    // Scenario 1: Registration ceremony (challenge → attestation → store)
    // ====================================================================

    #[test]
    fn registration_ceremony_none_attestation() {
        let helper = WebAuthnTestHelper::new("example.com");
        let challenge = generate_challenge().expect("generate");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };

        let (client_data_json, attestation_object) =
            helper.build_registration_response(&challenge, origin);

        let (info, stored) = complete_registration(
            &pending,
            &client_data_json,
            &attestation_object,
            origin,
            1_000_000,
        )
        .expect("registration should succeed");

        assert_eq!(info.credential_id(), helper.credential_id);
        assert_eq!(info.algorithm(), COSE_ALG_ES256);
        assert_eq!(stored.sign_count, 0);
        assert_eq!(stored.rp_id, "example.com");
    }

    #[test]
    fn registration_ceremony_packed_self_attestation() {
        let helper = WebAuthnTestHelper::new("example.com");
        let challenge = generate_challenge().expect("generate");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };

        let (client_data_json, attestation_object) =
            helper.build_packed_registration_response(&challenge, origin);

        let (info, stored) = complete_registration(
            &pending,
            &client_data_json,
            &attestation_object,
            origin,
            1_000_000,
        )
        .expect("packed self-attestation registration should succeed");

        assert_eq!(info.credential_id(), helper.credential_id);
        assert_eq!(info.algorithm(), COSE_ALG_ES256);
        assert_eq!(stored.algorithm, COSE_ALG_ES256);
    }

    // ====================================================================
    // Scenario 2: Authentication ceremony (challenge → assertion → counter)
    // ====================================================================

    #[test]
    fn authentication_ceremony_roundtrip() {
        let helper = WebAuthnTestHelper::new("example.com");
        let challenge = generate_challenge().expect("generate");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // First register to get a stored credential
        let reg_pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (reg_cdj, reg_att) = helper.build_registration_response(&challenge, origin);
        let (_info, stored) =
            complete_registration(&reg_pending, &reg_cdj, &reg_att, origin, 1_000_000)
                .expect("registration");

        // Now authenticate
        let auth_challenge = generate_challenge().expect("generate");
        let auth_pending = PendingWebAuthnChallenge {
            challenge: auth_challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };

        let (cdj, auth_data, sig, _handle) =
            helper.build_authentication_response(&auth_challenge, origin, 1, None);

        let result =
            complete_authentication(&auth_pending, &stored, &cdj, &auth_data, &sig, None, origin)
                .expect("authentication should succeed");

        assert_eq!(result.user_id(), &user_id);
        assert_eq!(result.sign_count(), 1);
        assert_eq!(result.credential_id(), helper.credential_id);
    }

    #[test]
    fn authentication_counter_updates() {
        let helper = WebAuthnTestHelper::new("example.com");
        let challenge = generate_challenge().expect("generate");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register
        let reg_pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (cdj, att) = helper.build_registration_response(&challenge, origin);
        let (_info, mut stored) =
            complete_registration(&reg_pending, &cdj, &att, origin, 1_000_000).expect("reg");

        // Auth with counter=1
        let c1 = generate_challenge().expect("gen");
        let p1 = PendingWebAuthnChallenge {
            challenge: c1.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };
        let (cdj1, ad1, sig1, _) = helper.build_authentication_response(&c1, origin, 1, None);
        let r1 = complete_authentication(&p1, &stored, &cdj1, &ad1, &sig1, None, origin)
            .expect("auth 1");
        assert_eq!(r1.sign_count(), 1);
        stored.sign_count = r1.sign_count();

        // Auth with counter=5 (authenticator can skip)
        let c2 = generate_challenge().expect("gen");
        let p2 = PendingWebAuthnChallenge {
            challenge: c2.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Authentication,
            created_at: 3_000_000,
        };
        let (cdj2, ad2, sig2, _) = helper.build_authentication_response(&c2, origin, 5, None);
        let r2 = complete_authentication(&p2, &stored, &cdj2, &ad2, &sig2, None, origin)
            .expect("auth 2");
        assert_eq!(r2.sign_count(), 5);
    }

    // ====================================================================
    // Scenario 3: Multi-credential (register multiple, each authenticates)
    // ====================================================================

    #[test]
    fn multi_credential_both_authenticate() {
        let helper1 = WebAuthnTestHelper::new("example.com");
        let helper2 = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register credential 1
        let c1 = generate_challenge().expect("gen");
        let p1 = PendingWebAuthnChallenge {
            challenge: c1.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (cdj1, att1) = helper1.build_registration_response(&c1, origin);
        let (info1, stored1) =
            complete_registration(&p1, &cdj1, &att1, origin, 1_000_000).expect("reg1");

        // Register credential 2
        let c2 = generate_challenge().expect("gen");
        let p2 = PendingWebAuthnChallenge {
            challenge: c2.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (cdj2, att2) = helper2.build_registration_response(&c2, origin);
        let (info2, stored2) =
            complete_registration(&p2, &cdj2, &att2, origin, 1_000_000).expect("reg2");

        // Each credential has a unique ID
        assert_ne!(info1.credential_id(), info2.credential_id());

        // Authenticate with credential 1
        {
            let challenge = generate_challenge().expect("gen");
            let pending = PendingWebAuthnChallenge {
                challenge: challenge.clone(),
                rp_id: "example.com".to_string(),
                user_id: Some(user_id.clone()),
                ceremony_type: CeremonyType::Authentication,
                created_at: 2_000_000,
            };
            let (cdj, auth_data, sig, _) =
                helper1.build_authentication_response(&challenge, origin, 1, None);
            let result =
                complete_authentication(&pending, &stored1, &cdj, &auth_data, &sig, None, origin)
                    .expect("auth with credential 1");
            assert_eq!(result.credential_id(), helper1.credential_id);
        }

        // Authenticate with credential 2
        {
            let challenge = generate_challenge().expect("gen");
            let pending = PendingWebAuthnChallenge {
                challenge: challenge.clone(),
                rp_id: "example.com".to_string(),
                user_id: Some(user_id.clone()),
                ceremony_type: CeremonyType::Authentication,
                created_at: 2_000_000,
            };
            let (cdj, auth_data, sig, _) =
                helper2.build_authentication_response(&challenge, origin, 1, None);
            let result =
                complete_authentication(&pending, &stored2, &cdj, &auth_data, &sig, None, origin)
                    .expect("auth with credential 2");
            assert_eq!(result.credential_id(), helper2.credential_id);
        }
    }

    // ====================================================================
    // Scenario 4: Resident key / discoverable credential (username-less auth)
    // ====================================================================

    #[test]
    fn discoverable_credential_username_less_auth() {
        let helper = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register as discoverable
        let reg_challenge = generate_challenge().expect("gen");
        let reg_pending = PendingWebAuthnChallenge {
            challenge: reg_challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (reg_cdj, reg_att) = helper.build_registration_response(&reg_challenge, origin);
        let (_info, stored) =
            complete_registration(&reg_pending, &reg_cdj, &reg_att, origin, 1_000_000)
                .expect("registration");

        // Authenticate WITHOUT user_id in pending (username-less)
        let auth_challenge = generate_challenge().expect("gen");
        let auth_pending = PendingWebAuthnChallenge {
            challenge: auth_challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: None, // No user specified — discoverable flow
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };

        // The authenticator provides userHandle containing the user UUID
        let user_handle_str = user_id.as_uuid().to_string();
        let (cdj, ad, sig, handle) = helper.build_authentication_response(
            &auth_challenge,
            origin,
            1,
            Some(&user_handle_str),
        );

        let result = complete_authentication(
            &auth_pending,
            &stored,
            &cdj,
            &ad,
            &sig,
            handle.as_deref(),
            origin,
        )
        .expect("discoverable auth should succeed");

        assert_eq!(result.user_id(), &user_id);
        assert_eq!(result.sign_count(), 1);
    }

    #[test]
    fn discoverable_auth_without_user_handle_fails() {
        let helper = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register
        let reg_c = generate_challenge().expect("gen");
        let reg_p = PendingWebAuthnChallenge {
            challenge: reg_c.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (cdj, att) = helper.build_registration_response(&reg_c, origin);
        let (_info, stored) =
            complete_registration(&reg_p, &cdj, &att, origin, 1_000_000).expect("reg");

        // Try discoverable auth without providing userHandle
        let auth_c = generate_challenge().expect("gen");
        let auth_p = PendingWebAuthnChallenge {
            challenge: auth_c.clone(),
            rp_id: "example.com".to_string(),
            user_id: None,
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };
        let (acdj, aad, asig, _) = helper.build_authentication_response(&auth_c, origin, 1, None);

        let result = complete_authentication(&auth_p, &stored, &acdj, &aad, &asig, None, origin);
        let err = result.expect_err("should fail without userHandle");
        assert!(err.to_string().contains("no user ID available"));
    }

    // ====================================================================
    // Scenario 5: Attestation formats (none, packed self, unsupported)
    // ====================================================================

    #[test]
    fn unsupported_attestation_format_rejected() {
        let helper = WebAuthnTestHelper::new("example.com");
        let challenge = generate_challenge().expect("gen");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };

        // Build a "tpm" attestation object (unsupported format)
        let client_data_json =
            WebAuthnTestHelper::build_client_data_json("webauthn.create", &challenge, origin);
        let auth_data = helper.build_auth_data(0, true);

        let att_obj = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("tpm".to_string()),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![]),
            ),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(auth_data),
            ),
        ]);
        let mut att_bytes = Vec::new();
        ciborium::into_writer(&att_obj, &mut att_bytes).expect("encode");

        let err = complete_registration(&pending, &client_data_json, &att_bytes, origin, 1_000_000)
            .expect_err("tpm should be rejected");
        assert!(err.to_string().contains("unsupported attestation format"));
    }

    #[test]
    fn packed_attestation_with_x5c_rejected() {
        let helper = WebAuthnTestHelper::new("example.com");
        let challenge = generate_challenge().expect("gen");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };

        let client_data_json =
            WebAuthnTestHelper::build_client_data_json("webauthn.create", &challenge, origin);
        let auth_data = helper.build_auth_data(0, true);

        // Packed with x5c (certificate chain) — not supported
        let att_obj = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_string()),
                ciborium::Value::Text("packed".to_string()),
            ),
            (
                ciborium::Value::Text("attStmt".to_string()),
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("alg".to_string()),
                        ciborium::Value::Integer((-7).into()),
                    ),
                    (
                        ciborium::Value::Text("sig".to_string()),
                        ciborium::Value::Bytes(vec![0u8; 64]),
                    ),
                    (
                        ciborium::Value::Text("x5c".to_string()),
                        ciborium::Value::Array(vec![ciborium::Value::Bytes(vec![0u8; 32])]),
                    ),
                ]),
            ),
            (
                ciborium::Value::Text("authData".to_string()),
                ciborium::Value::Bytes(auth_data),
            ),
        ]);
        let mut att_bytes = Vec::new();
        ciborium::into_writer(&att_obj, &mut att_bytes).expect("encode");

        let err = complete_registration(&pending, &client_data_json, &att_bytes, origin, 1_000_000)
            .expect_err("packed with x5c should be rejected");
        assert!(err
            .to_string()
            .contains("x5c certificate chain is not supported"));
    }

    // ====================================================================
    // Scenario 9: Sign counter replay (cloned authenticator detection)
    // ====================================================================

    #[test]
    fn sign_counter_replay_rejected() {
        let helper = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register
        let reg_challenge = generate_challenge().expect("gen");
        let reg_pending = PendingWebAuthnChallenge {
            challenge: reg_challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (reg_cdj, reg_att) = helper.build_registration_response(&reg_challenge, origin);
        let (_info, mut stored) =
            complete_registration(&reg_pending, &reg_cdj, &reg_att, origin, 1_000_000)
                .expect("registration");

        // First auth with counter=1 — should succeed
        {
            let challenge = generate_challenge().expect("gen");
            let pending = PendingWebAuthnChallenge {
                challenge: challenge.clone(),
                rp_id: "example.com".to_string(),
                user_id: Some(user_id.clone()),
                ceremony_type: CeremonyType::Authentication,
                created_at: 2_000_000,
            };
            let (cdj, auth_data, sig, _) =
                helper.build_authentication_response(&challenge, origin, 1, None);
            let result =
                complete_authentication(&pending, &stored, &cdj, &auth_data, &sig, None, origin)
                    .expect("first auth");
            assert_eq!(result.sign_count(), 1);
            stored.sign_count = result.sign_count();
        }

        // Replay with same counter=1 — should be rejected
        {
            let challenge = generate_challenge().expect("gen");
            let pending = PendingWebAuthnChallenge {
                challenge: challenge.clone(),
                rp_id: "example.com".to_string(),
                user_id: Some(user_id.clone()),
                ceremony_type: CeremonyType::Authentication,
                created_at: 3_000_000,
            };
            let (cdj, auth_data, sig, _) =
                helper.build_authentication_response(&challenge, origin, 1, None);
            let err =
                complete_authentication(&pending, &stored, &cdj, &auth_data, &sig, None, origin)
                    .expect_err("replay should be rejected");
            assert!(err.to_string().contains("sign counter did not increment"));
        }
    }

    #[test]
    fn sign_counter_zero_to_zero_accepted() {
        // Some authenticators always report counter=0 — this should be accepted
        // only when both stored and reported are 0 (first auth after registration).
        let helper = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        let reg_challenge = generate_challenge().expect("gen");
        let reg_pending = PendingWebAuthnChallenge {
            challenge: reg_challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (reg_cdj, reg_att) = helper.build_registration_response(&reg_challenge, origin);
        let (_info, stored) =
            complete_registration(&reg_pending, &reg_cdj, &reg_att, origin, 1_000_000)
                .expect("registration");
        assert_eq!(stored.sign_count, 0);

        // Auth with counter=0 when stored is also 0 — accepted (both-zero exception)
        let challenge = generate_challenge().expect("gen");
        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };
        let (cdj, auth_data, sig, _) =
            helper.build_authentication_response(&challenge, origin, 0, None);
        complete_authentication(&pending, &stored, &cdj, &auth_data, &sig, None, origin)
            .expect("zero-to-zero should be accepted");
    }

    // ====================================================================
    // Scenario 10: RP ID mismatch (wrong origin rejected)
    // ====================================================================

    #[test]
    fn rp_id_mismatch_rejected_on_authentication() {
        let helper = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register with rp_id="example.com"
        let reg_challenge = generate_challenge().expect("gen");
        let reg_pending = PendingWebAuthnChallenge {
            challenge: reg_challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (reg_cdj, reg_att) = helper.build_registration_response(&reg_challenge, origin);
        let (_info, stored) =
            complete_registration(&reg_pending, &reg_cdj, &reg_att, origin, 1_000_000)
                .expect("registration");

        // Build authenticator data with wrong RP ID hash
        let challenge = generate_challenge().expect("gen");
        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(), // Server expects example.com
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };

        // Authenticator data uses evil.com's RP ID hash
        let evil_auth_data = WebAuthnTestHelper::build_auth_data_custom_rp("evil.com", 1);
        let client_data_json =
            WebAuthnTestHelper::build_client_data_json("webauthn.get", &challenge, origin);

        // Sign the evil authData (signature would be valid for the bytes)
        let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &client_data_json);
        let mut signed_data = evil_auth_data.clone();
        signed_data.extend_from_slice(client_data_hash.as_ref());
        let sig = helper.sign(&signed_data);

        let err = complete_authentication(
            &pending,
            &stored,
            &client_data_json,
            &evil_auth_data,
            &sig,
            None,
            origin,
        )
        .expect_err("RP ID mismatch should be rejected");
        assert!(err.to_string().contains("RP ID hash mismatch"));
    }

    // ====================================================================
    // Scenario 11: Tampered clientDataJSON (modified challenge/origin fails)
    // ====================================================================

    #[test]
    fn tampered_challenge_in_client_data_rejected() {
        let helper = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register
        let reg_challenge = generate_challenge().expect("gen");
        let reg_pending = PendingWebAuthnChallenge {
            challenge: reg_challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (reg_cdj, reg_att) = helper.build_registration_response(&reg_challenge, origin);
        let (_info, stored) =
            complete_registration(&reg_pending, &reg_cdj, &reg_att, origin, 1_000_000)
                .expect("registration");

        // Build a legitimate authentication response
        let real_challenge = generate_challenge().expect("gen");
        let (legit_cdj, auth_data, sig, _) =
            helper.build_authentication_response(&real_challenge, origin, 1, None);

        // Tamper: replace clientDataJSON with one containing a different challenge
        let fake_challenge = generate_challenge().expect("gen");
        let tampered_cdj =
            WebAuthnTestHelper::build_client_data_json("webauthn.get", &fake_challenge, origin);

        // Use a pending that matches the tampered challenge (attacker controls this)
        let pending = PendingWebAuthnChallenge {
            challenge: fake_challenge,
            rp_id: "example.com".to_string(),
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };

        // Signature was over (authData || SHA-256(legit_cdj)) but we pass tampered_cdj
        // The hash mismatch means signature verification fails
        let _ = legit_cdj; // not used — signature was computed over this
        let err = complete_authentication(
            &pending,
            &stored,
            &tampered_cdj,
            &auth_data,
            &sig,
            None,
            origin,
        )
        .expect_err("tampered clientDataJSON should fail signature verification");
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn tampered_origin_in_client_data_rejected() {
        let helper = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register
        let reg_challenge = generate_challenge().expect("gen");
        let reg_pending = PendingWebAuthnChallenge {
            challenge: reg_challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (reg_cdj, reg_att) = helper.build_registration_response(&reg_challenge, origin);
        let (_info, stored) =
            complete_registration(&reg_pending, &reg_cdj, &reg_att, origin, 1_000_000)
                .expect("registration");

        // Build clientDataJSON with wrong origin
        let challenge = generate_challenge().expect("gen");
        let evil_cdj = WebAuthnTestHelper::build_client_data_json(
            "webauthn.get",
            &challenge,
            "https://evil.com",
        );

        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };

        // Build valid authData but sign with the evil cdj
        let auth_data = WebAuthnTestHelper::build_auth_data_custom_rp("example.com", 1);
        let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &evil_cdj);
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(client_data_hash.as_ref());
        let sig = helper.sign(&signed_data);

        // Origin check happens before signature verification
        let err =
            complete_authentication(&pending, &stored, &evil_cdj, &auth_data, &sig, None, origin)
                .expect_err("wrong origin should be rejected");
        assert!(err.to_string().contains("origin mismatch"));
    }

    // ====================================================================
    // Scenario 12: WebAuthn Level 2 ceremony conformance
    // ====================================================================

    /// Validates that the registration ceremony enforces all `WebAuthn` Level 2 requirements:
    /// - `clientDataJSON.type` == "webauthn.create"
    /// - Challenge match (base64url)
    /// - RP ID hash match (`SHA-256(rp_id)` == `authData[0..32]`)
    /// - UP (User Present) flag set
    /// - Attested credential data present
    /// - COSE key parseable with supported algorithm
    #[test]
    fn conformance_registration_enforces_all_fields() {
        let helper = WebAuthnTestHelper::new("example.com");
        let challenge = generate_challenge().expect("gen");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Challenge must be >= 16 bytes (we use 32)
        assert!(challenge.len() >= 16, "challenge must be at least 16 bytes");

        let pending = PendingWebAuthnChallenge {
            challenge: challenge.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };

        let (cdj, att) = helper.build_registration_response(&challenge, origin);

        // Verify clientDataJSON fields
        let client_data: serde_json::Value = serde_json::from_slice(&cdj).expect("parse cdj");
        assert_eq!(client_data["type"], "webauthn.create");
        assert_eq!(client_data["challenge"], URL_SAFE_NO_PAD.encode(&challenge));
        assert_eq!(client_data["origin"], origin);

        // Registration should succeed with all fields valid
        let (info, stored) = complete_registration(&pending, &cdj, &att, origin, 1_000_000)
            .expect("conformant registration");

        // Verify credential info
        assert!(!info.credential_id().is_empty());
        assert_eq!(info.algorithm(), COSE_ALG_ES256);
        assert_eq!(stored.rp_id, "example.com");

        // Wrong type should fail
        let wrong_type_cdj = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(&challenge),
            "origin": origin,
        }))
        .expect("json");
        let err = complete_registration(&pending, &wrong_type_cdj, &att, origin, 1_000_000);
        assert!(err.is_err());
    }

    /// Validates that the authentication ceremony enforces all `WebAuthn` Level 2 requirements:
    /// - `clientDataJSON.type` == "webauthn.get"
    /// - Challenge match
    /// - RP ID hash match
    /// - UP flag set
    /// - Valid signature over `authData || SHA-256(clientDataJSON)`
    #[test]
    fn conformance_authentication_enforces_all_fields() {
        let helper = WebAuthnTestHelper::new("example.com");
        let origin = "https://example.com";
        let user_id = UserId::generate();

        // Register
        let reg_c = generate_challenge().expect("gen");
        let reg_p = PendingWebAuthnChallenge {
            challenge: reg_c.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Registration,
            created_at: 1_000_000,
        };
        let (reg_cdj, reg_att) = helper.build_registration_response(&reg_c, origin);
        let (_info, stored) =
            complete_registration(&reg_p, &reg_cdj, &reg_att, origin, 1_000_000).expect("reg");

        // Authenticate
        let auth_c = generate_challenge().expect("gen");
        assert!(auth_c.len() >= 16);

        let auth_p = PendingWebAuthnChallenge {
            challenge: auth_c.clone(),
            rp_id: "example.com".to_string(),
            user_id: Some(user_id.clone()),
            ceremony_type: CeremonyType::Authentication,
            created_at: 2_000_000,
        };

        let (cdj, ad, sig, _) = helper.build_authentication_response(&auth_c, origin, 1, None);

        // Verify clientDataJSON fields
        let client_data: serde_json::Value = serde_json::from_slice(&cdj).expect("parse cdj");
        assert_eq!(client_data["type"], "webauthn.get");
        assert_eq!(client_data["challenge"], URL_SAFE_NO_PAD.encode(&auth_c));

        let result = complete_authentication(&auth_p, &stored, &cdj, &ad, &sig, None, origin)
            .expect("conformant authentication");
        assert_eq!(result.user_id(), &user_id);
        assert_eq!(result.sign_count(), 1);

        // Wrong type should fail
        let wrong_type_cdj = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.create",
            "challenge": URL_SAFE_NO_PAD.encode(&auth_c),
            "origin": origin,
        }))
        .expect("json");
        let err =
            complete_authentication(&auth_p, &stored, &wrong_type_cdj, &ad, &sig, None, origin);
        assert!(err.is_err());
    }
}
