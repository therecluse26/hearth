//! JWT token issuance, validation, and JWKS endpoint.
//!
//! Tokens are signed with Ed25519 (`EdDSA`) using the `ring` crate.
//! Only asymmetric signing is supported — no HMAC, no `alg: none`.
//!
//! Internal hot-path validation uses session lookup (not signature
//! re-verification). Full cryptographic validation is provided for
//! external consumers via the JWKS endpoint.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::core::Timestamp;
use crate::identity::error::IdentityError;

/// The only supported JWT algorithm.
const JWT_ALGORITHM: &str = "EdDSA";

/// The JWT type header value.
const JWT_TYPE: &str = "JWT";

/// Microseconds per second, for timestamp conversion.
const MICROS_PER_SEC: i64 = 1_000_000;

/// Configuration for token issuance.
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// The `iss` (issuer) claim value.
    pub issuer: String,
    /// The `aud` (audience) claim value.
    pub audience: String,
    /// Access token time-to-live in seconds.
    ///
    /// Default: 15 minutes (900 seconds).
    pub access_token_ttl_secs: i64,
    /// Refresh token time-to-live in seconds.
    ///
    /// Default: 7 days (604,800 seconds).
    pub refresh_token_ttl_secs: i64,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            issuer: "hearth".to_string(),
            audience: "hearth".to_string(),
            access_token_ttl_secs: 900,      // 15 minutes
            refresh_token_ttl_secs: 604_800, // 7 days
        }
    }
}

/// JWT header.
#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// JWT claims (payload).
///
/// Contains standard claims plus Hearth-specific claims for session
/// and realm binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    /// Subject — the user ID (or client ID for client credentials).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Expiration time (Unix seconds).
    pub exp: i64,
    /// Issued-at time (Unix seconds).
    pub iat: i64,
    /// Session ID — binds this token to a session.
    pub sid: String,
    /// Realm ID — binds this token to a realm.
    pub tid: String,
    /// Token type: `"access"` or `"refresh"`.
    pub token_type: String,
    /// JWT ID — unique identifier for this token (RFC 7519 §4.1.7).
    ///
    /// Ensures each issued JWT is unique even when all other claims
    /// are identical (e.g., during refresh token rotation within the
    /// same clock second).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Grant family ID — links tokens from the same authorization grant.
    ///
    /// Used for refresh token rotation and theft detection. When a
    /// refresh token is rotated, the new token inherits the same `fid`.
    /// If a previously-rotated token is reused, the entire family is
    /// revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fid: Option<String>,
    /// OAuth 2.0 scope string (space-delimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// OIDC nonce — echoed from the authorization request into the ID token.
    ///
    /// Per `OpenID` Connect Core 1.0 §2, when a nonce is provided in the
    /// authorization request, the ID token MUST include it unmodified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// A pair of access and refresh tokens.
#[derive(Debug, Clone)]
pub struct TokenPair {
    /// The short-lived access token (JWT).
    access_token: String,
    /// The long-lived refresh token (JWT).
    refresh_token: String,
}

impl TokenPair {
    /// Creates a new token pair from access and refresh token strings.
    pub(crate) fn new(access_token: String, refresh_token: String) -> Self {
        Self {
            access_token,
            refresh_token,
        }
    }

    /// Returns the access token string.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the refresh token string.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

/// A JSON Web Key for the JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key type — always `"OKP"` for Ed25519.
    pub kty: String,
    /// Curve — always `"Ed25519"`.
    pub crv: String,
    /// The public key, base64url-encoded.
    pub x: String,
    /// Key ID.
    pub kid: String,
    /// Key use — always `"sig"`.
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm — always `"EdDSA"`.
    pub alg: String,
}

/// JWKS document containing public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDocument {
    /// The set of JSON Web Keys.
    pub keys: Vec<Jwk>,
}

/// An Ed25519 signing key for JWT tokens.
///
/// Wraps `ring::signature::Ed25519KeyPair` with a deterministic key ID
/// derived from the public key. The PKCS#8 document is zeroized on drop.
pub struct SigningKey {
    /// The Ed25519 key pair used for signing.
    key_pair: Ed25519KeyPair,
    /// A stable key identifier derived from the public key.
    key_id: String,
    /// The raw PKCS#8 document, zeroized on drop.
    pkcs8_doc: ZeroizingBytes,
}

/// A wrapper around `Vec<u8>` that zeroizes on drop.
///
/// Used to protect raw key material in memory.
struct ZeroizingBytes(Vec<u8>);

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// SigningKey intentionally does not implement Debug/Display/Serialize
// to prevent key material leakage.
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generates a new random Ed25519 signing key.
    pub fn generate() -> Result<Self, IdentityError> {
        let rng = SystemRandom::new();
        let pkcs8_bytes =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| IdentityError::SigningError {
                reason: format!("key generation failed: {e}"),
            })?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).map_err(|e| {
            IdentityError::SigningError {
                reason: format!("key parsing failed: {e}"),
            }
        })?;
        let key_id = compute_key_id(key_pair.public_key().as_ref());
        Ok(Self {
            key_pair,
            key_id,
            pkcs8_doc: ZeroizingBytes(pkcs8_bytes.as_ref().to_vec()),
        })
    }

    /// Reconstructs a signing key from a PKCS#8 DER document.
    ///
    /// Used to load per-realm keys from storage.
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<Self, IdentityError> {
        let key_pair =
            Ed25519KeyPair::from_pkcs8(pkcs8_der).map_err(|e| IdentityError::SigningError {
                reason: format!("key parsing failed: {e}"),
            })?;
        let key_id = compute_key_id(key_pair.public_key().as_ref());
        Ok(Self {
            key_pair,
            key_id,
            pkcs8_doc: ZeroizingBytes(pkcs8_der.to_vec()),
        })
    }

    /// Returns a reference to the raw PKCS#8 DER bytes.
    ///
    /// Used to persist signing keys to storage. The caller MUST NOT
    /// log, display, or serialize these bytes.
    pub fn pkcs8_bytes(&self) -> &[u8] {
        &self.pkcs8_doc.0
    }

    /// Returns the key ID (derived from the public key).
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the public key bytes (32 bytes for Ed25519).
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Signs the given message and returns the signature bytes.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key_pair.sign(message).as_ref().to_vec()
    }

    /// Builds the JWK representation of the public key.
    pub fn to_jwk(&self) -> Jwk {
        Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(self.public_key_bytes()),
            kid: self.key_id.clone(),
            use_: "sig".to_string(),
            alg: JWT_ALGORITHM.to_string(),
        }
    }

    /// Builds a JWKS document containing this key.
    pub fn to_jwks(&self) -> JwksDocument {
        JwksDocument {
            keys: vec![self.to_jwk()],
        }
    }

    /// Issues a JWT with the given claims.
    pub fn issue_token(&self, claims: &TokenClaims) -> Result<String, IdentityError> {
        let header = JwtHeader {
            alg: JWT_ALGORITHM.to_string(),
            typ: JWT_TYPE.to_string(),
            kid: self.key_id.clone(),
        };

        let header_json =
            serde_json::to_vec(&header).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;
        let claims_json = serde_json::to_vec(claims).map_err(|e| IdentityError::Serialization {
            reason: e.to_string(),
        })?;

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = self.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Issues an access/refresh token pair for the given request.
    pub fn issue_token_pair(
        &self,
        request: &IssueTokenRequest,
    ) -> Result<TokenPair, IdentityError> {
        let iat = request.now.as_micros() / MICROS_PER_SEC;

        let access_claims = TokenClaims {
            sub: request.sub.to_string(),
            iss: request.config.issuer.clone(),
            aud: request.config.audience.clone(),
            exp: iat + request.config.access_token_ttl_secs,
            iat,
            sid: request.sid.to_string(),
            tid: request.tid.to_string(),
            token_type: "access".to_string(),
            jti: None,
            fid: None,
            scope: None,
            nonce: None,
        };

        let refresh_claims = TokenClaims {
            sub: request.sub.to_string(),
            iss: request.config.issuer.clone(),
            aud: request.config.audience.clone(),
            exp: iat + request.config.refresh_token_ttl_secs,
            iat,
            sid: request.sid.to_string(),
            tid: request.tid.to_string(),
            token_type: "refresh".to_string(),
            jti: None,
            fid: None,
            scope: None,
            nonce: None,
        };

        let access_token = self.issue_token(&access_claims)?;
        let refresh_token = self.issue_token(&refresh_claims)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }
}

/// Parameters for issuing a token pair.
#[derive(Debug)]
pub struct IssueTokenRequest<'a> {
    /// Subject — typically the user ID string.
    pub sub: &'a str,
    /// Session ID string.
    pub sid: &'a str,
    /// Realm ID string.
    pub tid: &'a str,
    /// Current timestamp.
    pub now: Timestamp,
    /// Token configuration (issuer, audience, TTLs).
    pub config: &'a TokenConfig,
}

/// Validates a JWT's signature and returns the decoded claims.
///
/// Performs full cryptographic validation:
/// 1. Splits the token into header.payload.signature
/// 2. Rejects any algorithm other than `EdDSA`
/// 3. Verifies the Ed25519 signature against the public key
/// 4. Decodes and returns the claims
///
/// Does NOT check expiration — callers must check `exp` themselves
/// or use [`validate_token_with_time`].
pub fn verify_token_signature(
    token: &str,
    public_key_bytes: &[u8],
) -> Result<TokenClaims, IdentityError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(IdentityError::InvalidToken);
    }

    // Decode and validate header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| IdentityError::InvalidToken)?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| IdentityError::InvalidToken)?;

    // Reject anything other than EdDSA
    if header.alg != JWT_ALGORITHM {
        return Err(IdentityError::InvalidToken);
    }
    if header.typ != JWT_TYPE {
        return Err(IdentityError::InvalidToken);
    }

    // Verify signature
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| IdentityError::InvalidToken)?;

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
    public_key
        .verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| IdentityError::InvalidToken)?;

    // Decode claims
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| IdentityError::InvalidToken)?;
    let claims: TokenClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| IdentityError::InvalidToken)?;

    Ok(claims)
}

/// Validates a JWT's signature and checks expiration against the given time.
///
/// Returns `Err(TokenExpired)` if `now >= exp`.
pub fn validate_token_with_time(
    token: &str,
    public_key_bytes: &[u8],
    now: Timestamp,
) -> Result<TokenClaims, IdentityError> {
    let claims = verify_token_signature(token, public_key_bytes)?;
    let now_secs = now.as_micros() / MICROS_PER_SEC;
    if now_secs >= claims.exp {
        return Err(IdentityError::TokenExpired);
    }
    Ok(claims)
}

/// Decodes JWT claims without verifying the signature.
///
/// Used internally for hot-path session extraction where Hearth
/// trusts its own tokens and validates via session lookup instead.
///
/// Returns `Err(InvalidToken)` if the token is malformed.
pub fn decode_claims_unverified(token: &str) -> Result<TokenClaims, IdentityError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(IdentityError::InvalidToken);
    }

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| IdentityError::InvalidToken)?;
    let claims: TokenClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| IdentityError::InvalidToken)?;

    Ok(claims)
}

/// Computes a deterministic key ID from Ed25519 public key bytes.
///
/// Uses SHA-256 of the public key, truncated to 16 bytes, base64url-encoded.
fn compute_key_id(public_key_bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, public_key_bytes);
    URL_SAFE_NO_PAD.encode(&digest.as_ref()[..16])
}

/// An RSA-2048 signing key for SAML XML-DSIG.
///
/// SAML uses RSA-SHA256 signatures almost universally; Hearth's JWT path
/// uses Ed25519 which is not interoperable with SAML SPs/IdPs. This type
/// mirrors [`SigningKey`]'s zeroize-on-drop + PKCS#8 DER round-trip posture
/// but for RSA. Per-realm RSA keys are generated lazily on first SAML
/// operation and persisted under the system realm.
pub struct RsaSigningKey {
    /// The raw PKCS#8 DER document, zeroized on drop.
    pkcs8_doc: ZeroizingBytes,
    /// `ring` key pair reconstructed from the PKCS#8 bytes, used for
    /// signing. `ring` signing is both fast and side-channel-hardened.
    ring_key: ring::signature::RsaKeyPair,
    /// Self-signed X.509 certificate DER (for embedding in SAML metadata).
    cert_der: Vec<u8>,
    /// SHA-256 fingerprint of the public key, truncated + base64url. Used
    /// as a kid in metadata descriptors.
    key_id: String,
}

impl std::fmt::Debug for RsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaSigningKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl RsaSigningKey {
    /// Generates a new RSA-2048 keypair and a self-signed X.509
    /// certificate bound to `subject_cn` (SAML metadata requires an X.509
    /// wrapper around the raw key).
    ///
    /// `valid_days` sets the certificate validity window. 3650 (10 years)
    /// is a common default for long-lived IdP signing certs.
    pub fn generate(subject_cn: &str, valid_days: u32) -> Result<Self, IdentityError> {
        use rsa::pkcs8::EncodePrivateKey as _;
        use rsa::RsaPrivateKey;

        // RSA keygen is genuinely slow (~0.5–1s on stock hardware). This
        // is off the hot path and called once per realm at most.
        let mut rng = rand_core::OsRng;
        let private =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| IdentityError::SigningError {
                reason: format!("RSA key generation failed: {e}"),
            })?;
        let pkcs8 = private
            .to_pkcs8_der()
            .map_err(|e| IdentityError::SigningError {
                reason: format!("RSA PKCS#8 encoding failed: {e}"),
            })?;
        let pkcs8_bytes = pkcs8.as_bytes().to_vec();

        let cert_der = build_self_signed_cert(&pkcs8_bytes, subject_cn, valid_days)?;

        Self::from_pkcs8_and_cert(&pkcs8_bytes, &cert_der)
    }

    /// Reconstructs an RSA signing key from stored PKCS#8 DER bytes plus
    /// the associated X.509 certificate DER.
    pub fn from_pkcs8_and_cert(pkcs8_der: &[u8], cert_der: &[u8]) -> Result<Self, IdentityError> {
        let ring_key = ring::signature::RsaKeyPair::from_pkcs8(pkcs8_der).map_err(|e| {
            IdentityError::SigningError {
                reason: format!("RSA PKCS#8 parse failed: {e}"),
            }
        })?;
        // key_id is derived from the PKCS#8 bytes (SHA-256 fingerprint,
        // truncated). Deterministic for a given key.
        let key_id = compute_key_id(pkcs8_der);
        Ok(Self {
            pkcs8_doc: ZeroizingBytes(pkcs8_der.to_vec()),
            ring_key,
            cert_der: cert_der.to_vec(),
            key_id,
        })
    }

    /// Returns the PKCS#8 DER bytes for persistence.
    ///
    /// Callers MUST NOT log or display these bytes.
    pub fn pkcs8_bytes(&self) -> &[u8] {
        &self.pkcs8_doc.0
    }

    /// Returns the self-signed X.509 certificate DER.
    ///
    /// Embedded in SAML metadata's `<X509Certificate>` element.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Returns the key identifier.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Signs `message` with RSA-PKCS1-v1.5-SHA256 and returns the
    /// signature bytes.
    ///
    /// The produced signature is exactly the byte string that goes into
    /// `<ds:SignatureValue>` after base64 encoding.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let mut sig = vec![0u8; self.ring_key.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();
        self.ring_key
            .sign(&ring::signature::RSA_PKCS1_SHA256, &rng, message, &mut sig)
            .map_err(|e| IdentityError::SigningError {
                reason: format!("RSA sign failed: {e}"),
            })?;
        Ok(sig)
    }
}

/// Builds a minimal self-signed X.509 certificate wrapping the RSA public
/// key extracted from `pkcs8_der`.
///
/// SAML metadata requires an X.509 wrapper; the cert's CN, validity, and
/// issuer are cosmetic — only the embedded `SubjectPublicKeyInfo` matters
/// for signature verification.
fn build_self_signed_cert(
    pkcs8_der: &[u8],
    subject_cn: &str,
    valid_days: u32,
) -> Result<Vec<u8>, IdentityError> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    // rcgen 0.13 cannot generate RSA keys itself, but it can consume a
    // PKCS#8 DER we already generated and sign a self-signed cert with it.
    let keypair = KeyPair::try_from(pkcs8_der).map_err(|e| IdentityError::SigningError {
        reason: format!("rcgen keypair load failed: {e}"),
    })?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject_cn);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    #[allow(clippy::cast_possible_wrap)]
    let days = i64::from(valid_days);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);

    let cert = params
        .self_signed(&keypair)
        .map_err(|e| IdentityError::SigningError {
            reason: format!("rcgen self-sign failed: {e}"),
        })?;
    Ok(cert.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;

    // ===== Helpers =====

    fn test_signing_key() -> SigningKey {
        SigningKey::generate().expect("key generation should succeed")
    }

    fn test_claims(now_secs: i64) -> TokenClaims {
        TokenClaims {
            sub: "user_550e8400-e29b-41d4-a716-446655440000".to_string(),
            iss: "hearth".to_string(),
            aud: "hearth".to_string(),
            exp: now_secs + 900, // 15 min
            iat: now_secs,
            sid: "session_660e8400-e29b-41d4-a716-446655440000".to_string(),
            tid: "realm_770e8400-e29b-41d4-a716-446655440000".to_string(),
            token_type: "access".to_string(),
            jti: None,
            fid: None,
            scope: None,
            nonce: None,
        }
    }

    // ===== Unit Test 1: Issue JWT with correct standard claims =====

    #[test]
    fn issue_jwt_has_correct_standard_claims() {
        let key = test_signing_key();
        let now_secs = 1_700_000_000_i64;
        let claims = test_claims(now_secs);

        let token = key.issue_token(&claims).expect("issue should succeed");

        // Token has three base64url parts
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");

        // Decode header
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("header decode");
        let header: JwtHeader = serde_json::from_slice(&header_bytes).expect("header parse");
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, "JWT");
        assert_eq!(header.kid, key.key_id());

        // Decode claims and verify standard fields
        let decoded_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("claims decode");
        let decoded: TokenClaims = serde_json::from_slice(&decoded_bytes).expect("claims parse");
        assert_eq!(decoded.sub, claims.sub, "sub mismatch");
        assert_eq!(decoded.iss, "hearth", "iss mismatch");
        assert_eq!(decoded.aud, "hearth", "aud mismatch");
        assert_eq!(decoded.exp, now_secs + 900, "exp mismatch");
        assert_eq!(decoded.iat, now_secs, "iat mismatch");
        assert_eq!(decoded.sid, claims.sid, "sid mismatch");
        assert_eq!(decoded.tid, claims.tid, "tid mismatch");
    }

    // ===== Unit Test 2: Validate JWT signature returns parsed claims =====

    #[test]
    fn validate_jwt_correct_signature_returns_claims() {
        let key = test_signing_key();
        let now_secs = 1_700_000_000_i64;
        let claims = test_claims(now_secs);

        let token = key.issue_token(&claims).expect("issue");

        let validated = verify_token_signature(&token, key.public_key_bytes())
            .expect("validation should succeed");

        assert_eq!(validated, claims);
    }

    // ===== Unit Test 3: Reject expired, tampered, and wrong-key JWTs =====

    #[test]
    fn reject_expired_jwt() {
        let key = test_signing_key();
        let past_secs = 1_600_000_000_i64;
        let claims = TokenClaims {
            exp: past_secs, // already expired
            ..test_claims(past_secs - 900)
        };

        let token = key.issue_token(&claims).expect("issue");

        // Signature is valid
        let verified = verify_token_signature(&token, key.public_key_bytes());
        assert!(verified.is_ok(), "signature should be valid");

        // But time-based validation rejects it
        let now = Timestamp::from_micros(past_secs * MICROS_PER_SEC + 1_000_000);
        let result = validate_token_with_time(&token, key.public_key_bytes(), now);
        assert!(
            matches!(result, Err(IdentityError::TokenExpired)),
            "expired token should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn reject_tampered_payload() {
        let key = test_signing_key();
        let claims = test_claims(1_700_000_000);

        let token = key.issue_token(&claims).expect("issue");

        // Tamper with the payload by replacing a character
        let parts: Vec<&str> = token.split('.').collect();
        let mut tampered_claims = URL_SAFE_NO_PAD.decode(parts[1]).expect("decode");
        if let Some(byte) = tampered_claims.get_mut(10) {
            *byte = byte.wrapping_add(1);
        }
        let tampered_b64 = URL_SAFE_NO_PAD.encode(&tampered_claims);
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_b64, parts[2]);

        let result = verify_token_signature(&tampered_token, key.public_key_bytes());
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "tampered token should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn reject_wrong_signing_key() {
        let key1 = test_signing_key();
        let key2 = test_signing_key();
        let claims = test_claims(1_700_000_000);

        let token = key1.issue_token(&claims).expect("issue with key1");

        // Verify with key2's public key — should fail
        let result = verify_token_signature(&token, key2.public_key_bytes());
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "wrong key should be rejected, got: {result:?}"
        );
    }

    // ===== Unit Test 4: Token refresh issues new JWT with extended expiration =====

    #[test]
    fn token_pair_refresh_has_extended_expiration() {
        let key = test_signing_key();
        let now = Timestamp::from_micros(1_700_000_000 * MICROS_PER_SEC);
        let now_secs = 1_700_000_000_i64;
        let config = TokenConfig {
            issuer: "hearth".to_string(),
            audience: "hearth".to_string(),
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 604_800,
        };

        let pair = key
            .issue_token_pair(&IssueTokenRequest {
                sub: "user_abc",
                sid: "session_xyz",
                tid: "realm_123",
                now,
                config: &config,
            })
            .expect("issue pair");

        // Verify access token claims
        let access_claims = verify_token_signature(pair.access_token(), key.public_key_bytes())
            .expect("access token valid");
        assert_eq!(access_claims.exp, now_secs + config.access_token_ttl_secs);
        assert_eq!(access_claims.token_type, "access");

        // Verify refresh token claims
        let refresh_claims = verify_token_signature(pair.refresh_token(), key.public_key_bytes())
            .expect("refresh token valid");
        assert_eq!(refresh_claims.exp, now_secs + config.refresh_token_ttl_secs);
        assert_eq!(refresh_claims.token_type, "refresh");

        // Refresh token expires later than access token
        assert!(
            refresh_claims.exp > access_claims.exp,
            "refresh token should expire later than access token"
        );

        // Simulate refresh: issue new pair at a later time
        let later = Timestamp::from_micros((now_secs + 600) * MICROS_PER_SEC);
        let later_secs = now_secs + 600;
        let new_pair = key
            .issue_token_pair(&IssueTokenRequest {
                sub: "user_abc",
                sid: "session_xyz",
                tid: "realm_123",
                now: later,
                config: &config,
            })
            .expect("reissue pair");

        let new_access = verify_token_signature(new_pair.access_token(), key.public_key_bytes())
            .expect("new access valid");
        assert_eq!(new_access.exp, later_secs + config.access_token_ttl_secs);
        assert!(
            new_access.exp > access_claims.exp,
            "refreshed token should have later expiration"
        );
    }

    // ===== Unit Test 5: JWKS endpoint returns correct public keys =====

    #[test]
    fn jwks_returns_correct_public_key_format() {
        let key = test_signing_key();
        let jwks = key.to_jwks();

        assert_eq!(jwks.keys.len(), 1, "should have exactly one key");

        let jwk = &jwks.keys[0];
        assert_eq!(jwk.kty, "OKP", "key type must be OKP");
        assert_eq!(jwk.crv, "Ed25519", "curve must be Ed25519");
        assert_eq!(jwk.alg, "EdDSA", "algorithm must be EdDSA");
        assert_eq!(jwk.use_, "sig", "use must be sig");
        assert_eq!(jwk.kid, key.key_id(), "kid must match signing key id");

        // Verify the public key in JWK matches the signing key
        let decoded_pub = URL_SAFE_NO_PAD
            .decode(&jwk.x)
            .expect("x should be valid base64url");
        assert_eq!(
            decoded_pub,
            key.public_key_bytes(),
            "JWK public key must match signing key"
        );

        // Verify JWKS is valid JSON
        let json = serde_json::to_string_pretty(&jwks).expect("JWKS should serialize");
        assert!(json.contains("\"keys\""), "JWKS must have keys array");
    }

    #[test]
    fn jwks_key_can_verify_issued_token() {
        let key = test_signing_key();
        let claims = test_claims(1_700_000_000);
        let token = key.issue_token(&claims).expect("issue");

        // Extract public key from JWKS
        let jwks = key.to_jwks();
        let jwk = &jwks.keys[0];
        let pub_bytes = URL_SAFE_NO_PAD
            .decode(&jwk.x)
            .expect("decode pub from JWKS");

        // Verify the token using the JWKS-provided public key
        let validated = verify_token_signature(&token, &pub_bytes).expect("should verify");
        assert_eq!(validated, claims);
    }

    // ===== Additional unit tests =====

    #[test]
    fn signing_key_debug_does_not_leak_key_material() {
        let key = test_signing_key();
        let debug = format!("{key:?}");
        assert!(debug.contains("SigningKey"), "should contain type name");
        assert!(debug.contains("key_id"), "should contain key_id field");
        // Must not contain raw key bytes
        assert!(!debug.contains("pkcs8"), "must not leak pkcs8");
    }

    #[test]
    fn key_id_is_deterministic_for_same_key() {
        let key = test_signing_key();
        let kid1 = key.key_id().to_string();
        let kid2 = compute_key_id(key.public_key_bytes());
        assert_eq!(kid1, kid2, "key ID must be deterministic");
    }

    #[test]
    fn different_keys_have_different_key_ids() {
        let key1 = test_signing_key();
        let key2 = test_signing_key();
        assert_ne!(
            key1.key_id(),
            key2.key_id(),
            "different keys should have different IDs"
        );
    }

    #[test]
    fn decode_claims_unverified_extracts_claims() {
        let key = test_signing_key();
        let claims = test_claims(1_700_000_000);
        let token = key.issue_token(&claims).expect("issue");

        let decoded = decode_claims_unverified(&token).expect("decode");
        assert_eq!(decoded, claims);
    }

    #[test]
    fn decode_claims_unverified_rejects_malformed() {
        assert!(matches!(
            decode_claims_unverified("not.a.valid.jwt"),
            Err(IdentityError::InvalidToken)
        ));
        assert!(matches!(
            decode_claims_unverified("onlytwoparts.here"),
            Err(IdentityError::InvalidToken)
        ));
        assert!(matches!(
            decode_claims_unverified(""),
            Err(IdentityError::InvalidToken)
        ));
    }

    #[test]
    fn reject_alg_none_header() {
        let key = test_signing_key();
        let claims = test_claims(1_700_000_000);

        // Craft a token with alg: none
        let header = JwtHeader {
            alg: "none".to_string(),
            typ: "JWT".to_string(),
            kid: key.key_id().to_string(),
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("ser"));
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("ser"));
        // Empty signature
        let token = format!("{header_b64}.{claims_b64}.");

        let result = verify_token_signature(&token, key.public_key_bytes());
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "alg=none must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn reject_unsupported_algorithm() {
        let key = test_signing_key();
        let claims = test_claims(1_700_000_000);

        // Craft a token with alg: HS256
        let header = JwtHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
            kid: key.key_id().to_string(),
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("ser"));
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("ser"));
        let token = format!("{header_b64}.{claims_b64}.fakesig");

        let result = verify_token_signature(&token, key.public_key_bytes());
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "HS256 must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn token_config_default_values() {
        let config = TokenConfig::default();
        assert_eq!(config.issuer, "hearth");
        assert_eq!(config.audience, "hearth");
        assert_eq!(config.access_token_ttl_secs, 900);
        assert_eq!(config.refresh_token_ttl_secs, 604_800);
    }

    // ===== Adversarial Tests =====

    /// Adversarial: `alg=none` attack — unsigned token rejected regardless of claims.
    #[test]
    fn adversarial_alg_none_with_valid_claims_rejected() {
        let key = test_signing_key();
        let claims = test_claims(1_700_000_000);

        // Issue a real token, then re-wrap with alg: none
        let token = key.issue_token(&claims).expect("issue");
        let parts: Vec<&str> = token.split('.').collect();

        // Replace header with alg=none, keep valid payload and empty sig
        let none_header = JwtHeader {
            alg: "none".to_string(),
            typ: "JWT".to_string(),
            kid: key.key_id().to_string(),
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&none_header).expect("ser"));
        let stripped = format!("{header_b64}.{}.", parts[1]);

        let result = verify_token_signature(&stripped, key.public_key_bytes());
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "alg=none attack must be rejected even with valid claims"
        );
    }

    /// Adversarial: RSA/HMAC key confusion — HMAC-signed token using public key as secret.
    ///
    /// This tests the classic JWT confusion attack where an attacker crafts an
    /// HS256-signed token using the RSA/Ed25519 public key as the HMAC secret.
    /// Hearth rejects this because it only accepts `EdDSA` — any other algorithm
    /// is rejected at the header check before signature verification.
    #[test]
    fn adversarial_hmac_key_confusion_rejected() {
        let key = test_signing_key();
        let claims = test_claims(1_700_000_000);

        // Craft HS256 header (attacker would sign with public key as HMAC secret)
        let confused_header = JwtHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
            kid: key.key_id().to_string(),
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&confused_header).expect("ser"));
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("ser"));

        // Use public key bytes as HMAC "signature" (simulating the attack)
        let fake_sig = URL_SAFE_NO_PAD.encode(key.public_key_bytes());
        let token = format!("{header_b64}.{claims_b64}.{fake_sig}");

        let result = verify_token_signature(&token, key.public_key_bytes());
        assert!(
            matches!(result, Err(IdentityError::InvalidToken)),
            "HMAC key confusion attack must be rejected, got: {result:?}"
        );

        // Also try with RS256
        let rs_header = JwtHeader {
            alg: "RS256".to_string(),
            typ: "JWT".to_string(),
            kid: key.key_id().to_string(),
        };
        let rs_header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&rs_header).expect("ser"));
        let rs_token = format!("{rs_header_b64}.{claims_b64}.{fake_sig}");

        let rs_result = verify_token_signature(&rs_token, key.public_key_bytes());
        assert!(
            matches!(rs_result, Err(IdentityError::InvalidToken)),
            "RS256 confusion attack must be rejected, got: {rs_result:?}"
        );
    }

    /// Adversarial: Modified `exp`, `iss`, or `aud` claims detected and rejected.
    ///
    /// If an attacker modifies any claim in the payload, the Ed25519 signature
    /// becomes invalid. This verifies that the signature check catches it.
    #[test]
    fn adversarial_modified_claims_detected() {
        let key = test_signing_key();
        let claims = test_claims(1_700_000_000);
        let token = key.issue_token(&claims).expect("issue");
        let parts: Vec<&str> = token.split('.').collect();

        // Modify exp to extend token lifetime
        let mut modified = claims.clone();
        modified.exp = claims.exp + 86400; // extend by 1 day
        let mod_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&modified).expect("ser"));
        let tampered = format!("{}.{}.{}", parts[0], mod_b64, parts[2]);
        assert!(
            matches!(
                verify_token_signature(&tampered, key.public_key_bytes()),
                Err(IdentityError::InvalidToken)
            ),
            "modified exp must be rejected"
        );

        // Modify iss to impersonate another issuer
        let mut modified_iss = claims.clone();
        modified_iss.iss = "evil-issuer".to_string();
        let iss_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&modified_iss).expect("ser"));
        let tampered_iss = format!("{}.{}.{}", parts[0], iss_b64, parts[2]);
        assert!(
            matches!(
                verify_token_signature(&tampered_iss, key.public_key_bytes()),
                Err(IdentityError::InvalidToken)
            ),
            "modified iss must be rejected"
        );

        // Modify aud to target a different audience
        let mut modified_aud = claims.clone();
        modified_aud.aud = "other-service".to_string();
        let aud_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&modified_aud).expect("ser"));
        let tampered_aud = format!("{}.{}.{}", parts[0], aud_b64, parts[2]);
        assert!(
            matches!(
                verify_token_signature(&tampered_aud, key.public_key_bytes()),
                Err(IdentityError::InvalidToken)
            ),
            "modified aud must be rejected"
        );

        // Modify sub to impersonate another user
        let mut modified_sub = claims;
        modified_sub.sub = "user_attacker".to_string();
        let sub_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&modified_sub).expect("ser"));
        let tampered_sub = format!("{}.{}.{}", parts[0], sub_b64, parts[2]);
        assert!(
            matches!(
                verify_token_signature(&tampered_sub, key.public_key_bytes()),
                Err(IdentityError::InvalidToken)
            ),
            "modified sub must be rejected"
        );
    }

    /// Adversarial: Completely empty and garbage inputs never panic.
    #[test]
    fn adversarial_garbage_input_never_panics() {
        let key = test_signing_key();
        let pub_key = key.public_key_bytes();

        // These should all return Err, never panic
        let cases = [
            "",
            ".",
            "..",
            "...",
            "a.b.c",
            "not-base64.also-not.base64",
            "\0\0\0.\0\0\0.\0\0\0",
            &"A".repeat(10_000),
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.e30.",
        ];

        for input in &cases {
            // verify_token_signature
            let result = verify_token_signature(input, pub_key);
            assert!(result.is_err(), "should reject garbage: {input:?}");

            // decode_claims_unverified
            let result2 = decode_claims_unverified(input);
            assert!(
                result2.is_err(),
                "unverified should reject garbage: {input:?}"
            );

            // validate_token_with_time
            let now = Timestamp::from_micros(1_700_000_000 * MICROS_PER_SEC);
            let result3 = validate_token_with_time(input, pub_key, now);
            assert!(
                result3.is_err(),
                "timed validation should reject garbage: {input:?}"
            );
        }
    }
}
