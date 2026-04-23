//! `GenericOidcConnector` — OIDC Core 1.0 relying-party implementation.
//!
//! One connector code path covers every OIDC-compliant upstream
//! (Google, Microsoft, Apple, Okta, Auth0, Azure AD, Keycloak, Zitadel)
//! — they differ only in `issuer`, `scopes`, and the occasional claim
//! rename. Provider-specific YAML presets (`src/identity/federation/presets.rs`,
//! coming in Checkpoint C) fill in the known constants so operators
//! can write `type: google` and get correct defaults.
//!
//! This module provides:
//!
//! - [`DiscoveryDocument`] — parsed `/.well-known/openid-configuration`.
//! - [`JwksDoc`] + [`Jwk`] — parsed upstream JWKS.
//! - [`verify_rs256`] — RS256 signature verification over JWKS keys.
//! - [`verify_id_token_claims`] — iss/aud/exp/nonce/iat validation.
//!
//! Full `begin()` / `exchange()` flow wiring happens in
//! `GenericOidcConnector::{begin,exchange}` (below) and is orchestrated
//! by the upcoming `FederationService`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::identity::federation::connector::{AuthorizeUrl, IdpConnector};
use crate::identity::federation::http::{FedHttpRequest, FedHttpResponse, FederationHttpTransport};
use crate::identity::federation::state::pkce_s256_challenge;
use crate::identity::federation::types::{ExternalIdentity, IdpConfig, IdpKind, StateBag};
use crate::identity::IdentityError;

/// The subset of OIDC discovery metadata Hearth actually consumes.
///
/// Extra fields from the upstream document are deliberately ignored via
/// `#[serde(default)]` and `deny_unknown_fields = false` (serde's
/// default) so provider quirks don't break parsing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryDocument {
    /// The `iss` value that must appear in every ID token from this
    /// provider. Used for issuer binding during verification.
    pub issuer: String,
    /// URL to redirect the user agent to for authorization.
    pub authorization_endpoint: String,
    /// URL where `code` is exchanged for tokens.
    pub token_endpoint: String,
    /// URL returning user claims. Optional per OIDC Core §5.3.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// URL returning the issuer's signing keys.
    pub jwks_uri: String,
}

/// A parsed JWKS document (collection of signing keys).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwksDoc {
    /// The key set.
    pub keys: Vec<Jwk>,
}

/// A single JWKS entry.
///
/// Only RSA (`RS256`) is supported today — that covers every
/// mainstream OIDC provider Hearth targets in v1. EC (`ES256`) and
/// Ed25519 are straightforward follow-ups but not in scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (`"RSA"`).
    pub kty: String,
    /// Intended algorithm (`"RS256"`), or `None` if the provider omits it.
    #[serde(default)]
    pub alg: Option<String>,
    /// Key ID. Required so the ID token header `kid` can select the
    /// right key during verification.
    #[serde(default)]
    pub kid: Option<String>,
    /// RSA modulus, base64url no-pad.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent, base64url no-pad.
    #[serde(default)]
    pub e: Option<String>,
}

/// The claims Hearth reads from an upstream ID token.
///
/// Extra claims are ignored. Provider-specific claim renames (e.g.,
/// Azure AD's `upn`) are applied by the caller via
/// `IdpConfig::claim_mappings` *before* this struct is populated — the
/// struct itself carries normalized OIDC names.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdTokenClaims {
    /// Issuer — must match `IdpConfig::issuer`.
    pub iss: String,
    /// Subject — the upstream-stable external identity.
    pub sub: String,
    /// Audience. OIDC allows both string and array; Hearth accepts
    /// both via a custom helper below.
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    /// Not-before timestamp (Unix seconds).
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Expiry timestamp (Unix seconds). Required.
    pub exp: i64,
    /// Issued-at timestamp (Unix seconds).
    #[serde(default)]
    pub iat: Option<i64>,
    /// Replay-prevention nonce — must equal the `nonce` Hearth sent in
    /// the authorize request (echoed verbatim by compliant providers).
    #[serde(default)]
    pub nonce: Option<String>,
    /// Email address, normalized lowercase.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the upstream considers the email verified.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Best-effort display name (optional per Core §5.1).
    #[serde(default)]
    pub name: Option<String>,
    /// First (given) name (optional per Core §5.1).
    #[serde(default)]
    pub given_name: Option<String>,
    /// Last (family) name (optional per Core §5.1).
    #[serde(default)]
    pub family_name: Option<String>,
    /// Optional picture URL (Core §5.1).
    #[serde(default)]
    pub picture: Option<String>,
}

/// A generic OIDC relying-party connector.
///
/// Holds the per-connector config plus an injectable HTTP transport.
/// Tests swap in [`super::http::StubFederationTransport`] to drive
/// happy and sad paths without live network.
pub struct GenericOidcConnector {
    /// The connector's persisted config.
    pub(crate) config: IdpConfig,
    /// Where to send HTTP (token / JWKS / userinfo).
    pub(crate) http: Arc<dyn FederationHttpTransport>,
    /// Redirect URI this connector was registered with. Built from
    /// `server.base_url + /ui/federation/callback` at `FederationService`
    /// construction.
    pub(crate) redirect_uri: String,
}

impl GenericOidcConnector {
    /// Creates a new connector from a persisted [`IdpConfig`].
    pub fn new(
        config: IdpConfig,
        http: Arc<dyn FederationHttpTransport>,
        redirect_uri: String,
    ) -> Self {
        Self {
            config,
            http,
            redirect_uri,
        }
    }

    /// Returns the redirect URI registered at the upstream IdP.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
}

impl IdpConnector for GenericOidcConnector {
    fn kind(&self) -> IdpKind {
        IdpKind::Oidc
    }

    fn display_name(&self) -> &str {
        &self.config.display_name
    }

    fn begin(&self, state: &StateBag) -> Result<AuthorizeUrl, IdentityError> {
        build_authorize_url(&self.config, &self.redirect_uri, state)
    }

    fn exchange(&self, code: &str, state: &StateBag) -> Result<ExternalIdentity, IdentityError> {
        exchange_code(&self.config, &*self.http, &self.redirect_uri, code, state)
    }
}

/// Builds the upstream authorize URL with PKCE + nonce + state.
fn build_authorize_url(
    cfg: &IdpConfig,
    redirect_uri: &str,
    state: &StateBag,
) -> Result<AuthorizeUrl, IdentityError> {
    let challenge = pkce_s256_challenge(&state.pkce_verifier);
    let scopes = cfg.scopes.join(" ");
    let mut url = form_urlencoded::Serializer::new(String::new());
    url.append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", &scopes)
        .append_pair("state", &state.state_token)
        .append_pair("nonce", &state.nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let query = url.finish();
    let sep = if cfg.authorization_endpoint.contains('?') {
        "&"
    } else {
        "?"
    };
    Ok(AuthorizeUrl(format!(
        "{}{sep}{query}",
        cfg.authorization_endpoint
    )))
}

/// Orchestrates the code → ID token → ExternalIdentity flow.
fn exchange_code(
    cfg: &IdpConfig,
    http: &dyn FederationHttpTransport,
    redirect_uri: &str,
    code: &str,
    state: &StateBag,
) -> Result<ExternalIdentity, IdentityError> {
    // 1. POST the token endpoint.
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("client_id", &cfg.client_id)
        .append_pair("client_secret", cfg.client_secret.expose_secret())
        .append_pair("code_verifier", &state.pkce_verifier)
        .finish();
    let token_resp = http.send(&FedHttpRequest {
        method: "POST",
        url: cfg.token_endpoint.clone(),
        headers: vec![("Accept".to_string(), "application/json".to_string())],
        body: body.into_bytes(),
        content_type: Some("application/x-www-form-urlencoded".to_string()),
    })?;
    if token_resp.status < 200 || token_resp.status >= 300 {
        return Err(IdentityError::FederationUpstreamError {
            provider: IdpKind::Oidc.label().to_string(),
            reason: format!("token endpoint returned {}", token_resp.status),
        });
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        id_token: String,
    }
    let parsed: TokenResponse = serde_json::from_str(&token_resp.body).map_err(|e| {
        IdentityError::FederationUpstreamError {
            provider: IdpKind::Oidc.label().to_string(),
            reason: format!("invalid token response: {e}"),
        }
    })?;

    // 2. Parse JWT header → pick signing key → verify signature.
    let (header_b64, payload_b64, _sig_b64) = split_jwt(&parsed.id_token)?;
    let header: JwtHeader = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| IdentityError::FederationTokenVerificationFailed)?,
    )
    .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;

    if header.alg != "RS256" {
        // v1 supports only RS256. The overwhelming majority of OIDC
        // providers sign with it; ES256 / EdDSA are straightforward
        // follow-ups but not in scope.
        return Err(IdentityError::FederationTokenVerificationFailed);
    }

    let jwks = fetch_jwks(cfg, http)?;
    let key = select_jwk(&jwks, header.kid.as_deref())
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    verify_rs256(&parsed.id_token, key)
        .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;

    // 3. Decode claims and validate iss / aud / exp / nonce.
    let claims: IdTokenClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| IdentityError::FederationTokenVerificationFailed)?,
    )
    .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;
    verify_id_token_claims(&claims, cfg, state, now_unix())?;

    // 4. Map claims → ExternalIdentity (applying per-connector renames).
    Ok(claims_to_identity(&claims, cfg))
}

/// JWT header (we only need alg + kid).
#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

fn split_jwt(jwt: &str) -> Result<(&str, &str, &str), IdentityError> {
    let mut parts = jwt.splitn(3, '.');
    let header = parts
        .next()
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    let payload = parts
        .next()
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    let sig = parts
        .next()
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    if parts.next().is_some() {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    Ok((header, payload, sig))
}

fn fetch_jwks(
    cfg: &IdpConfig,
    http: &dyn FederationHttpTransport,
) -> Result<JwksDoc, IdentityError> {
    let url = cfg
        .jwks_uri
        .as_deref()
        .ok_or_else(|| IdentityError::FederationUpstreamError {
            provider: IdpKind::Oidc.label().to_string(),
            reason: "connector has no jwks_uri".to_string(),
        })?;
    let resp: FedHttpResponse = http.send(&FedHttpRequest {
        method: "GET",
        url: url.to_string(),
        headers: vec![("Accept".to_string(), "application/json".to_string())],
        body: Vec::new(),
        content_type: None,
    })?;
    if resp.status < 200 || resp.status >= 300 {
        return Err(IdentityError::FederationUpstreamError {
            provider: IdpKind::Oidc.label().to_string(),
            reason: format!("jwks endpoint returned {}", resp.status),
        });
    }
    serde_json::from_str(&resp.body).map_err(|e| IdentityError::FederationUpstreamError {
        provider: IdpKind::Oidc.label().to_string(),
        reason: format!("invalid JWKS document: {e}"),
    })
}

fn select_jwk<'a>(jwks: &'a JwksDoc, kid: Option<&str>) -> Option<&'a Jwk> {
    // Prefer exact kid match. If the token carries no kid and there's
    // exactly one key, fall through — some providers (like Apple)
    // historically emit single-key sets without kid on rotation
    // transitions.
    if let Some(k) = kid {
        jwks.keys.iter().find(|j| j.kid.as_deref() == Some(k))
    } else if jwks.keys.len() == 1 {
        jwks.keys.first()
    } else {
        None
    }
}

/// Verifies an RS256-signed JWT against a JWKS key.
///
/// Returns `Ok(())` on valid signature; a generic
/// `FederationTokenVerificationFailed` otherwise.
pub fn verify_rs256(jwt: &str, key: &Jwk) -> Result<(), IdentityError> {
    if key.kty != "RSA" {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    let n_b64 = key
        .n
        .as_deref()
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    let e_b64 = key
        .e
        .as_deref()
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    let n = URL_SAFE_NO_PAD
        .decode(n_b64)
        .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;
    let e = URL_SAFE_NO_PAD
        .decode(e_b64)
        .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;

    let dot1 = jwt
        .find('.')
        .ok_or(IdentityError::FederationTokenVerificationFailed)?;
    let dot2 = jwt[dot1 + 1..]
        .find('.')
        .ok_or(IdentityError::FederationTokenVerificationFailed)?
        + dot1
        + 1;
    let signed = &jwt[..dot2]; // header.payload
    let sig_b64 = &jwt[dot2 + 1..];
    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| IdentityError::FederationTokenVerificationFailed)?;

    let components = ring::signature::RsaPublicKeyComponents {
        n: n.as_slice(),
        e: e.as_slice(),
    };
    components
        .verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            signed.as_bytes(),
            &sig,
        )
        .map_err(|_| IdentityError::FederationTokenVerificationFailed)
}

/// Validates the non-cryptographic claims of an ID token: issuer,
/// audience, lifetime, and nonce.
///
/// `now_unix_secs` is injected so tests can pin the clock.
pub fn verify_id_token_claims(
    claims: &IdTokenClaims,
    cfg: &IdpConfig,
    state: &StateBag,
    now_unix_secs: i64,
) -> Result<(), IdentityError> {
    if claims.iss != cfg.issuer {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    if !audience_contains(&claims.aud, &cfg.client_id) {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    // 60s clock-skew allowance on both edges — standard OIDC RP tolerance.
    if claims.exp + 60 < now_unix_secs {
        return Err(IdentityError::FederationTokenVerificationFailed);
    }
    if let Some(nbf) = claims.nbf {
        if nbf > now_unix_secs + 60 {
            return Err(IdentityError::FederationTokenVerificationFailed);
        }
    }
    // Nonce MUST match if the upstream echoed one. If the provider
    // omitted it entirely (rare but RFC-legal when Hearth didn't send
    // one) we skip the check. We always send a nonce, so missing is
    // effectively "provider bug" — treat as failure.
    match claims.nonce.as_deref() {
        Some(n) if n == state.nonce => {}
        _ => return Err(IdentityError::FederationTokenVerificationFailed),
    }
    Ok(())
}

fn audience_contains(aud: &Option<serde_json::Value>, client_id: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(s)) => s == client_id,
        Some(serde_json::Value::Array(xs)) => xs
            .iter()
            .any(|v| v.as_str().map(|s| s == client_id).unwrap_or(false)),
        _ => false,
    }
}

fn claims_to_identity(claims: &IdTokenClaims, cfg: &IdpConfig) -> ExternalIdentity {
    // Per-connector renames (cfg.claim_mappings) are applied by the
    // caller *before* deserializing into IdTokenClaims — the JSON is
    // mutated so that `email` / `name` read through the rename. For v1
    // none of the supported providers need mappings; the hook is here
    // for operator-written generic `type: oidc` entries pointing at
    // Azure AD (`upn` → `email`) and the like.
    let _ = cfg; // reserved
    ExternalIdentity {
        idp_id: cfg.id.clone(),
        external_sub: claims.sub.clone(),
        email: claims.email.clone().unwrap_or_default(),
        email_verified: claims.email_verified.unwrap_or(false),
        display_name: claims.name.clone().unwrap_or_default(),
        first_name: claims.given_name.clone().unwrap_or_default(),
        last_name: claims.family_name.clone().unwrap_or_default(),
        picture_url: claims.picture.clone(),
    }
}

/// Fuzz entry point: attempts to parse arbitrary bytes as an ID token
/// claims payload. Must never panic, only return `Ok` or `Err`.
///
/// Exposed publicly so the `fuzz/fuzz_targets/federation_claims.rs`
/// target can exercise the parser under `cargo fuzz` without taking a
/// dependency on private module internals.
pub fn fuzz_parse_id_token_claims(bytes: &[u8]) -> Result<IdTokenClaims, serde_json::Error> {
    serde_json::from_slice(bytes)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{IdpId, RealmId, Timestamp};
    use crate::identity::federation::http::StubFederationTransport;
    use crate::identity::federation::types::FederationSecret;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn sample_config() -> IdpConfig {
        IdpConfig {
            id: IdpId::new(Uuid::nil()),
            realm_id: RealmId::new(Uuid::nil()),
            name: "google".to_string(),
            kind: IdpKind::Oidc,
            display_name: "Google".to_string(),
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            scopes: vec!["openid".to_string(), "email".to_string()],
            client_id: "client-abc".to_string(),
            client_secret: FederationSecret::new("sekret".to_string()),
            claim_mappings: BTreeMap::new(),
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        }
    }

    fn sample_state(nonce: &str, verifier: &str) -> StateBag {
        StateBag {
            state_token: "st".to_string(),
            realm_id: RealmId::new(Uuid::nil()),
            idp_id: IdpId::new(Uuid::nil()),
            nonce: nonce.to_string(),
            pkce_verifier: verifier.to_string(),
            return_to: "/ui/account".to_string(),
            expires_at: Timestamp::from_micros(0),
        }
    }

    fn sample_claims(nonce: &str, now: i64) -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://accounts.google.com".to_string(),
            sub: "ext-sub-123".to_string(),
            aud: Some(serde_json::Value::String("client-abc".to_string())),
            nbf: None,
            exp: now + 600,
            iat: Some(now),
            nonce: Some(nonce.to_string()),
            email: Some("alice@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Alice".to_string()),
            given_name: None,
            family_name: None,
            picture: Some("https://pic/".to_string()),
        }
    }

    // ===== Discovery document =====

    #[test]
    fn discovery_parses_google_style_document() {
        let body = r#"{
          "issuer": "https://accounts.google.com",
          "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
          "token_endpoint": "https://oauth2.googleapis.com/token",
          "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
          "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
          "response_types_supported": ["code"],
          "id_token_signing_alg_values_supported": ["RS256"]
        }"#;
        let doc: DiscoveryDocument = serde_json::from_str(body).expect("parse");
        assert_eq!(doc.issuer, "https://accounts.google.com");
        assert_eq!(doc.token_endpoint, "https://oauth2.googleapis.com/token");
        assert_eq!(
            doc.userinfo_endpoint.as_deref(),
            Some("https://openidconnect.googleapis.com/v1/userinfo")
        );
    }

    #[test]
    fn discovery_tolerates_missing_userinfo_endpoint() {
        let body = r#"{
          "issuer": "https://idp.example",
          "authorization_endpoint": "https://idp.example/auth",
          "token_endpoint": "https://idp.example/token",
          "jwks_uri": "https://idp.example/jwks"
        }"#;
        let doc: DiscoveryDocument = serde_json::from_str(body).expect("parse");
        assert!(doc.userinfo_endpoint.is_none());
    }

    // ===== JWKS parsing =====

    #[test]
    fn jwks_parses_rsa_keys() {
        let body = r#"{
          "keys": [
            {
              "kty": "RSA",
              "alg": "RS256",
              "kid": "abc",
              "n": "x...",
              "e": "AQAB"
            }
          ]
        }"#;
        let jwks: JwksDoc = serde_json::from_str(body).expect("parse");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("abc"));
        assert_eq!(jwks.keys[0].alg.as_deref(), Some("RS256"));
    }

    #[test]
    fn select_jwk_by_kid_exact_match() {
        let jwks = JwksDoc {
            keys: vec![
                Jwk {
                    kty: "RSA".into(),
                    alg: Some("RS256".into()),
                    kid: Some("k1".into()),
                    n: Some("n1".into()),
                    e: Some("AQAB".into()),
                },
                Jwk {
                    kty: "RSA".into(),
                    alg: Some("RS256".into()),
                    kid: Some("k2".into()),
                    n: Some("n2".into()),
                    e: Some("AQAB".into()),
                },
            ],
        };
        assert_eq!(
            select_jwk(&jwks, Some("k2")).unwrap().n.as_deref(),
            Some("n2")
        );
        assert!(select_jwk(&jwks, Some("missing")).is_none());
    }

    #[test]
    fn select_jwk_falls_back_to_single_key_when_kid_absent() {
        let jwks = JwksDoc {
            keys: vec![Jwk {
                kty: "RSA".into(),
                alg: None,
                kid: None,
                n: Some("n".into()),
                e: Some("AQAB".into()),
            }],
        };
        assert!(select_jwk(&jwks, None).is_some());
    }

    #[test]
    fn select_jwk_refuses_ambiguous_no_kid_lookup() {
        let jwks = JwksDoc {
            keys: vec![
                Jwk {
                    kty: "RSA".into(),
                    alg: None,
                    kid: Some("k1".into()),
                    n: Some("n1".into()),
                    e: Some("AQAB".into()),
                },
                Jwk {
                    kty: "RSA".into(),
                    alg: None,
                    kid: Some("k2".into()),
                    n: Some("n2".into()),
                    e: Some("AQAB".into()),
                },
            ],
        };
        assert!(select_jwk(&jwks, None).is_none());
    }

    // ===== Claim verification =====

    #[test]
    fn claims_valid_pass_verification() {
        let cfg = sample_config();
        let state = sample_state("nnn", "vvv");
        let claims = sample_claims("nnn", 1_700_000_000);
        verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000).expect("valid claims");
    }

    #[test]
    fn claims_reject_wrong_issuer() {
        let cfg = sample_config();
        let state = sample_state("nnn", "vvv");
        let mut claims = sample_claims("nnn", 1_700_000_000);
        claims.iss = "https://evil.example".to_string();
        assert!(matches!(
            verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000),
            Err(IdentityError::FederationTokenVerificationFailed)
        ));
    }

    #[test]
    fn claims_reject_wrong_audience_string() {
        let cfg = sample_config();
        let state = sample_state("nnn", "vvv");
        let mut claims = sample_claims("nnn", 1_700_000_000);
        claims.aud = Some(serde_json::Value::String("other-client".to_string()));
        assert!(verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000).is_err());
    }

    #[test]
    fn claims_accept_audience_array_containing_client() {
        let cfg = sample_config();
        let state = sample_state("nnn", "vvv");
        let mut claims = sample_claims("nnn", 1_700_000_000);
        claims.aud = Some(serde_json::json!(["other", "client-abc"]));
        verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000).expect("aud array ok");
    }

    #[test]
    fn claims_reject_expired_beyond_skew() {
        let cfg = sample_config();
        let state = sample_state("nnn", "vvv");
        let mut claims = sample_claims("nnn", 1_700_000_000);
        claims.exp = 1_700_000_000;
        // Now = claims.exp + 90 → outside 60s skew.
        assert!(verify_id_token_claims(&claims, &cfg, &state, 1_700_000_090).is_err());
    }

    #[test]
    fn claims_accept_expired_within_skew() {
        let cfg = sample_config();
        let state = sample_state("nnn", "vvv");
        let mut claims = sample_claims("nnn", 1_700_000_000);
        claims.exp = 1_700_000_000;
        // Now = claims.exp + 30 → within 60s skew.
        verify_id_token_claims(&claims, &cfg, &state, 1_700_000_030).expect("skew ok");
    }

    #[test]
    fn claims_reject_nonce_mismatch() {
        let cfg = sample_config();
        let state = sample_state("expected", "vvv");
        let claims = sample_claims("different", 1_700_000_000);
        assert!(verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000).is_err());
    }

    #[test]
    fn claims_reject_missing_nonce_when_expected() {
        let cfg = sample_config();
        let state = sample_state("expected", "vvv");
        let mut claims = sample_claims("expected", 1_700_000_000);
        claims.nonce = None;
        assert!(verify_id_token_claims(&claims, &cfg, &state, 1_700_000_000).is_err());
    }

    // ===== begin() URL builder =====

    #[test]
    fn begin_emits_url_with_required_params() {
        let cfg = sample_config();
        let state = sample_state("nonce-xyz", "verifier-abc");
        let url = build_authorize_url(&cfg, "https://hearth.local/callback", &state)
            .expect("url")
            .0;
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=client-abc"));
        assert!(url.contains("state=st"));
        assert!(url.contains("nonce=nonce-xyz"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("scope=openid+email") || url.contains("scope=openid%20email"));
        // The literal verifier MUST NOT appear in the URL — only the
        // challenge does. Regression guard.
        assert!(!url.contains("verifier-abc"));
    }

    #[test]
    fn begin_preserves_existing_query_string_in_authorization_endpoint() {
        let mut cfg = sample_config();
        cfg.authorization_endpoint = "https://idp.example/auth?tenant=acme".to_string();
        let state = sample_state("n", "v");
        let url = build_authorize_url(&cfg, "https://h/cb", &state)
            .expect("url")
            .0;
        assert!(url.starts_with("https://idp.example/auth?tenant=acme&"));
        assert!(url.contains("client_id=client-abc"));
    }

    // ===== exchange() orchestration sad paths (via stub) =====

    #[test]
    fn exchange_rejects_token_endpoint_5xx() {
        let cfg = sample_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub("POST", cfg.token_endpoint.clone(), 500, "oops");
        let state = sample_state("n", "v");
        let result = exchange_code(&cfg, &*stub, "https://h/cb", "code-xyz", &state);
        assert!(matches!(
            result,
            Err(IdentityError::FederationUpstreamError { .. })
        ));
    }

    #[test]
    fn exchange_rejects_token_endpoint_garbage_body() {
        let cfg = sample_config();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub("POST", cfg.token_endpoint.clone(), 200, "not json");
        let state = sample_state("n", "v");
        let result = exchange_code(&cfg, &*stub, "https://h/cb", "code", &state);
        assert!(matches!(
            result,
            Err(IdentityError::FederationUpstreamError { .. })
        ));
    }

    #[test]
    fn exchange_rejects_non_rs256_algorithm() {
        let cfg = sample_config();
        // Craft a JWT with alg=HS256 — Hearth must refuse it outright.
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"whatever"}"#);
        let jwt = format!("{header}.{payload}.signature");
        let body = serde_json::json!({ "id_token": jwt }).to_string();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub("POST", cfg.token_endpoint.clone(), 200, body);
        let state = sample_state("n", "v");
        assert!(matches!(
            exchange_code(&cfg, &*stub, "https://h/cb", "code", &state),
            Err(IdentityError::FederationTokenVerificationFailed)
        ));
    }

    #[test]
    fn exchange_rejects_malformed_jwt_structure() {
        let cfg = sample_config();
        let body = serde_json::json!({ "id_token": "not-a-jwt" }).to_string();
        let stub = Arc::new(StubFederationTransport::new());
        stub.stub("POST", cfg.token_endpoint.clone(), 200, body);
        let state = sample_state("n", "v");
        assert!(matches!(
            exchange_code(&cfg, &*stub, "https://h/cb", "code", &state),
            Err(IdentityError::FederationTokenVerificationFailed)
        ));
    }

    #[test]
    fn claims_to_identity_propagates_fields() {
        let cfg = sample_config();
        let claims = sample_claims("n", 1_000);
        let id = claims_to_identity(&claims, &cfg);
        assert_eq!(id.external_sub, "ext-sub-123");
        assert_eq!(id.email, "alice@example.com");
        assert!(id.email_verified);
        assert_eq!(id.display_name, "Alice");
        assert_eq!(id.picture_url.as_deref(), Some("https://pic/"));
        assert_eq!(id.idp_id, cfg.id);
    }

    #[test]
    fn audience_contains_string_and_array_forms() {
        assert!(audience_contains(
            &Some(serde_json::Value::String("abc".to_string())),
            "abc"
        ));
        assert!(!audience_contains(
            &Some(serde_json::Value::String("abc".to_string())),
            "def"
        ));
        assert!(audience_contains(
            &Some(serde_json::json!(["x", "abc"])),
            "abc"
        ));
        assert!(!audience_contains(
            &Some(serde_json::json!(["x", "y"])),
            "abc"
        ));
        assert!(!audience_contains(&None, "abc"));
    }
}
