//! Federation domain types.
//!
//! These types describe external Identity Provider (IdP) connectors
//! registered against a realm for social login / federated sign-in.
//! No I/O, no framework types — pure domain.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::core::{IdpId, RealmId, Timestamp, UserId};

/// What flavor of external IdP protocol a connector speaks.
///
/// `Oidc` is the catch-all for OIDC Core 1.0-compliant providers
/// (Google, Microsoft, Apple, Okta, Auth0, Azure AD, Keycloak, Zitadel).
/// `GitHub` has its own variant because GitHub only implements OAuth2
/// (no ID token, custom `/user` + `/user/emails` endpoints).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdpKind {
    /// OIDC 1.0-compliant provider (uses discovery + ID token).
    #[serde(rename = "oidc")]
    Oidc,
    /// GitHub OAuth2 (no OIDC; uses `/user` + `/user/emails`).
    ///
    /// Serialized as `"github"` (not `"git_hub"` — `snake_case`
    /// auto-rename would split on the camel boundary). The wire form
    /// must match `IdpKind::label()` so YAML configs, storage, and
    /// audit events stay aligned.
    #[serde(rename = "github")]
    GitHub,
    /// SAML 2.0 IdP (SP-side — Hearth consumes assertions from upstream).
    #[serde(rename = "saml")]
    Saml,
}

impl IdpKind {
    /// Returns a stable lowercase label used in audit events, button
    /// `data-*` attributes, and logs. Never contains PII.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::GitHub => "github",
            Self::Saml => "saml",
        }
    }
}

/// How external logins interact with an existing local user when an
/// external IdP asserts a verified email that matches a Hearth user's
/// email address.
///
/// Matches Keycloak's "First Broker Login" semantics:
///
/// - `Disabled` — never link. Always JIT-provision a new user per
///   external identity. Safest; produces duplicate accounts.
/// - `Confirm` — on email match, redirect to a page that requires the
///   user to authenticate to their **local** account (password or
///   passkey) to prove ownership, then link. Keycloak's default and
///   Hearth's default.
/// - `Auto` — silent link when the external IdP asserts
///   `email_verified=true` and the email matches. Trusts the IdP
///   entirely. Only safe when the realm federates to a single
///   high-trust IdP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkMode {
    /// Never link; always JIT-provision.
    Disabled,
    /// Link only after the user re-authenticates locally.
    #[default]
    Confirm,
    /// Silently link on verified-email match.
    Auto,
}

/// A secret value (client secret, HMAC key, etc.) that must never
/// appear in `Debug`, `Display`, or serialized logs.
///
/// Serializes as the raw string so it round-trips through JSON
/// persistence, but `Debug` prints `***` and the wrapper is zeroized
/// on drop. Callers MUST NOT log the return value of `expose_secret`.
#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
#[serde(transparent)]
pub struct FederationSecret {
    inner: String,
}

impl FederationSecret {
    /// Creates a new secret from a string.
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    /// Returns the secret value. Callers MUST NOT log the return value.
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }

    /// Returns whether the secret is empty (caller passed `""`).
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for FederationSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FederationSecret(***)")
    }
}

impl PartialEq for FederationSecret {
    fn eq(&self, other: &Self) -> bool {
        // Not constant-time; connector configs are admin-authored and
        // compared only in equality contexts (reconcile diff), never in
        // credential validation.
        self.inner == other.inner
    }
}

impl Eq for FederationSecret {}

/// An external IdP connector registered against a realm.
///
/// Persisted as `fed:idp:{idp_uuid}` JSON under the owning realm's
/// key space. Created by `reconcile_federation_for_realm`, never by
/// end-user HTTP. The YAML is the source of truth; there is no admin
/// UI for CRUD in v1.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdpConfig {
    /// Unique connector ID within the realm.
    pub id: IdpId,
    /// Realm this connector belongs to.
    pub realm_id: RealmId,
    /// Stable operator-assigned name used in URLs (`?idp={name}`),
    /// YAML keys, and audit events. Matches `[a-z0-9_-]+`.
    pub name: String,
    /// Connector protocol.
    pub kind: IdpKind,
    /// Human-readable label rendered on the login button ("Sign in
    /// with {display_name}"). Defaults to a title-cased name.
    pub display_name: String,
    /// Issuer URL (OIDC `iss`). For `IdpKind::GitHub` this is
    /// `"https://github.com"` — used for audit, never for ID-token
    /// verification (GitHub has no ID token).
    pub issuer: String,
    /// Upstream authorization endpoint. For OIDC, fetched from
    /// discovery; for GitHub, hardcoded.
    pub authorization_endpoint: String,
    /// Upstream token endpoint.
    pub token_endpoint: String,
    /// Upstream userinfo endpoint. For OIDC, fetched from discovery;
    /// for GitHub, hardcoded to `/user`.
    pub userinfo_endpoint: Option<String>,
    /// Upstream JWKS endpoint. `None` for non-OIDC (GitHub).
    pub jwks_uri: Option<String>,
    /// OAuth scopes requested on `authorize`.
    pub scopes: Vec<String>,
    /// OAuth `client_id` registered at the upstream IdP.
    pub client_id: String,
    /// OAuth `client_secret`.
    pub client_secret: FederationSecret,
    /// Optional per-claim name overrides (e.g., `"email": "upn"` for
    /// Azure AD). Empty for standard OIDC providers.
    #[serde(default)]
    pub claim_mappings: BTreeMap<String, String>,
    /// When this connector was first registered.
    pub created_at: Timestamp,
    /// When the connector config was last updated by reconcile.
    pub updated_at: Timestamp,
}

/// A resolved external identity, extracted from an ID token or
/// userinfo response after successful upstream authentication.
///
/// The caller produces `ExternalIdentity` inside the connector's
/// `exchange()` method; downstream code never talks to the upstream
/// provider directly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalIdentity {
    /// Connector that produced this identity.
    pub idp_id: IdpId,
    /// Upstream-assigned stable subject identifier. Provider
    /// commits to its stability (Google `sub`, GitHub numeric `id`,
    /// Apple `sub`, etc.). Used as the primary link key.
    pub external_sub: String,
    /// Email address asserted by the upstream. May be empty if the
    /// provider returns no email (GitHub with private email, for
    /// instance — callers should handle `None` semantics via
    /// `is_empty()`).
    pub email: String,
    /// Whether the upstream considers the email verified. When `false`,
    /// auto-linking to an existing local user is refused regardless of
    /// realm `LinkMode` to prevent account hijack via IdP impersonation.
    pub email_verified: bool,
    /// Best-available display name (OIDC `name`, GitHub `name` or
    /// `login`). May be empty.
    pub display_name: String,
    /// Optional picture URL (OIDC `picture`, GitHub `avatar_url`).
    pub picture_url: Option<String>,
}

/// Short-lived state bag persisted between the `begin` redirect and
/// the `callback` completion of a federation login.
///
/// Stored at `fed:state:{opaque_token}` with a 10-minute TTL and
/// consumed single-use on callback (`take_federation_state` deletes
/// the row before returning).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateBag {
    /// Opaque token echoed as the OAuth `state` parameter. Random
    /// 256 bits, base64url, no padding.
    pub state_token: String,
    /// Realm this login is for (embedded so callback can resolve the
    /// right realm without re-parsing the URL path).
    pub realm_id: RealmId,
    /// Connector this login is for.
    pub idp_id: IdpId,
    /// OIDC nonce echoed in the ID token. Ignored for non-OIDC.
    pub nonce: String,
    /// PKCE code verifier (S256 is mandatory). Empty for connectors
    /// that don't use PKCE (e.g., confidential GitHub app).
    pub pkce_verifier: String,
    /// Return-to path inside the Hearth UI after successful login.
    /// Validated against a same-origin allowlist before being used.
    pub return_to: String,
    /// Absolute expiry (Unix microseconds). `take_federation_state`
    /// rejects entries past this timestamp.
    pub expires_at: Timestamp,
}

/// A pending external identity parked while the user confirms-to-link.
///
/// Created when `link_existing_accounts = Confirm` and a callback
/// produced an email match with an existing local user. Stored at
/// `fed:confirm:{ticket_uuid}` with a 10-minute TTL. Consumed by the
/// user successfully re-authenticating locally on
/// `/ui/federation/confirm-link`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfirmLinkTicket {
    /// Opaque single-use ticket (UUID string).
    pub ticket: String,
    /// Realm this link is for.
    pub realm_id: RealmId,
    /// Hearth user the external identity will attach to. The browser
    /// cookie carrying this ticket is HMAC-bound to `(user_id, ticket)`
    /// to prevent cross-user replay.
    pub user_id: UserId,
    /// The pending external identity.
    pub identity: ExternalIdentity,
    /// Absolute expiry (Unix microseconds).
    pub expires_at: Timestamp,
}

impl ExternalIdentity {
    /// Returns whether `email` is non-empty AND verified by the upstream.
    /// Only identities that return `true` are eligible for email-based
    /// linking under any `LinkMode`.
    pub fn is_linkable_by_email(&self) -> bool {
        self.email_verified && !self.email.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_identity(verified: bool, email: &str) -> ExternalIdentity {
        ExternalIdentity {
            idp_id: IdpId::generate(),
            external_sub: "sub-123".to_string(),
            email: email.to_string(),
            email_verified: verified,
            display_name: "Alice".to_string(),
            picture_url: None,
        }
    }

    #[test]
    fn idp_kind_label_is_stable() {
        assert_eq!(IdpKind::Oidc.label(), "oidc");
        assert_eq!(IdpKind::GitHub.label(), "github");
    }

    #[test]
    fn idp_kind_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&IdpKind::Oidc).expect("ser"),
            r#""oidc""#
        );
        assert_eq!(
            serde_json::to_string(&IdpKind::GitHub).expect("ser"),
            r#""github""#
        );
    }

    #[test]
    fn link_mode_default_is_confirm() {
        let m: LinkMode = LinkMode::default();
        assert_eq!(m, LinkMode::Confirm);
    }

    #[test]
    fn link_mode_round_trips_snake_case() {
        for mode in [LinkMode::Disabled, LinkMode::Confirm, LinkMode::Auto] {
            let j = serde_json::to_string(&mode).expect("ser");
            let back: LinkMode = serde_json::from_str(&j).expect("deser");
            assert_eq!(mode, back);
        }
        assert_eq!(
            serde_json::to_string(&LinkMode::Disabled).expect("ser"),
            r#""disabled""#
        );
        assert_eq!(
            serde_json::to_string(&LinkMode::Confirm).expect("ser"),
            r#""confirm""#
        );
        assert_eq!(
            serde_json::to_string(&LinkMode::Auto).expect("ser"),
            r#""auto""#
        );
    }

    #[test]
    fn federation_secret_debug_is_redacted() {
        let s = FederationSecret::new("super-secret".to_string());
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "FederationSecret(***)");
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn federation_secret_exposes_value_on_request() {
        let s = FederationSecret::new("abc".to_string());
        assert_eq!(s.expose_secret(), "abc");
    }

    #[test]
    fn federation_secret_is_empty_reports_empty() {
        assert!(FederationSecret::new(String::new()).is_empty());
        assert!(!FederationSecret::new("x".to_string()).is_empty());
    }

    #[test]
    fn federation_secret_round_trips_through_json() {
        let s = FederationSecret::new("my-secret".to_string());
        let j = serde_json::to_string(&s).expect("ser");
        // Transparent serde — the secret serializes as a plain string.
        assert_eq!(j, r#""my-secret""#);
        let back: FederationSecret = serde_json::from_str(&j).expect("deser");
        assert_eq!(back.expose_secret(), "my-secret");
    }

    #[test]
    fn external_identity_linkable_by_email_requires_verified_and_nonempty() {
        assert!(sample_identity(true, "alice@example.com").is_linkable_by_email());
        assert!(!sample_identity(false, "alice@example.com").is_linkable_by_email());
        assert!(!sample_identity(true, "").is_linkable_by_email());
        assert!(!sample_identity(false, "").is_linkable_by_email());
    }

    #[test]
    fn idp_config_round_trips_through_json() {
        let cfg = IdpConfig {
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
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            client_id: "client-xyz".to_string(),
            client_secret: FederationSecret::new("sekret".to_string()),
            claim_mappings: BTreeMap::new(),
            created_at: Timestamp::from_micros(1),
            updated_at: Timestamp::from_micros(2),
        };
        let j = serde_json::to_string(&cfg).expect("ser");
        // Secret is transparent — it round-trips but is not visible in Debug.
        assert!(j.contains("sekret"));
        let back: IdpConfig = serde_json::from_str(&j).expect("deser");
        assert_eq!(cfg, back);
        // But Debug doesn't leak it.
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("sekret"), "Debug must redact secret: {dbg}");
        assert!(dbg.contains("FederationSecret(***)"));
    }

    #[test]
    fn state_bag_round_trips() {
        let bag = StateBag {
            state_token: "abc".to_string(),
            realm_id: RealmId::new(Uuid::nil()),
            idp_id: IdpId::new(Uuid::nil()),
            nonce: "nonce".to_string(),
            pkce_verifier: "verifier".to_string(),
            return_to: "/ui/account".to_string(),
            expires_at: Timestamp::from_micros(1),
        };
        let j = serde_json::to_string(&bag).expect("ser");
        let back: StateBag = serde_json::from_str(&j).expect("deser");
        assert_eq!(bag, back);
    }

    #[test]
    fn confirm_link_ticket_round_trips() {
        let t = ConfirmLinkTicket {
            ticket: "t1".to_string(),
            realm_id: RealmId::new(Uuid::nil()),
            user_id: UserId::new(Uuid::nil()),
            identity: sample_identity(true, "alice@example.com"),
            expires_at: Timestamp::from_micros(1),
        };
        let j = serde_json::to_string(&t).expect("ser");
        let back: ConfirmLinkTicket = serde_json::from_str(&j).expect("deser");
        assert_eq!(t, back);
    }

    #[test]
    fn external_identity_round_trips() {
        let id = sample_identity(true, "a@b.c");
        let j = serde_json::to_string(&id).expect("ser");
        let back: ExternalIdentity = serde_json::from_str(&j).expect("deser");
        assert_eq!(id, back);
    }
}
