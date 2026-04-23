//! Hardcoded presets for well-known providers.
//!
//! YAML operators write `type: google` (or `microsoft` / `apple` /
//! `github`) and get correct issuer/endpoint/scope defaults without
//! having to look them up. The `oidc` (generic) and `github` types
//! require operators to supply all endpoints themselves.
//!
//! If a provider rotates an endpoint (rare but it happens — Microsoft
//! has done it), operators can still override any field in YAML.

use crate::identity::federation::types::IdpKind;

/// A preset fills in protocol constants for a well-known provider.
///
/// Only the fields providers differ on are in the preset; operator
/// YAML supplies `client_id`, `client_secret`, and (optionally)
/// `display_name`.
#[derive(Debug, Clone)]
pub struct Preset {
    /// Operator-assigned name (matches the preset label).
    pub name: &'static str,
    /// Kind — OIDC for google/microsoft/apple, GitHub for github.
    pub kind: IdpKind,
    /// Default `display_name` (used on the login button).
    pub display_name: &'static str,
    /// Default issuer URL.
    pub issuer: &'static str,
    /// Default authorization endpoint.
    pub authorization_endpoint: &'static str,
    /// Default token endpoint.
    pub token_endpoint: &'static str,
    /// Default userinfo endpoint (or `None`).
    pub userinfo_endpoint: Option<&'static str>,
    /// Default JWKS URL (or `None` for OAuth2-only providers).
    pub jwks_uri: Option<&'static str>,
    /// Default OAuth scopes.
    pub default_scopes: &'static [&'static str],
}

/// Looks up a preset by name. `None` for names that aren't hardcoded
/// (operators must use `type: oidc` and supply endpoints themselves).
pub fn lookup(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name)
}

const PRESETS: &[Preset] = &[
    Preset {
        name: "google",
        kind: IdpKind::Oidc,
        display_name: "Google",
        issuer: "https://accounts.google.com",
        authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint: "https://oauth2.googleapis.com/token",
        userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo"),
        jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs"),
        default_scopes: &["openid", "email", "profile"],
    },
    Preset {
        name: "microsoft",
        kind: IdpKind::Oidc,
        // "common" endpoint works for both personal and work/school
        // tenants. Single-tenant deployments override `issuer` and the
        // endpoints with their tenant id.
        display_name: "Microsoft",
        issuer: "https://login.microsoftonline.com/common/v2.0",
        authorization_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        userinfo_endpoint: Some("https://graph.microsoft.com/oidc/userinfo"),
        jwks_uri: Some("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
        default_scopes: &["openid", "email", "profile"],
    },
    Preset {
        name: "apple",
        kind: IdpKind::Oidc,
        display_name: "Apple",
        issuer: "https://appleid.apple.com",
        authorization_endpoint: "https://appleid.apple.com/auth/authorize",
        token_endpoint: "https://appleid.apple.com/auth/token",
        userinfo_endpoint: None, // Apple inlines claims in the ID token.
        jwks_uri: Some("https://appleid.apple.com/auth/keys"),
        default_scopes: &["openid", "email", "name"],
    },
    Preset {
        name: "github",
        kind: IdpKind::GitHub,
        display_name: "GitHub",
        issuer: "https://github.com",
        authorization_endpoint: "https://github.com/login/oauth/authorize",
        token_endpoint: "https://github.com/login/oauth/access_token",
        userinfo_endpoint: Some("https://api.github.com/user"),
        jwks_uri: None, // no OIDC / no JWKS.
        default_scopes: &["read:user", "user:email"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_presets_lookup() {
        assert_eq!(lookup("google").unwrap().kind, IdpKind::Oidc);
        assert_eq!(lookup("microsoft").unwrap().kind, IdpKind::Oidc);
        assert_eq!(lookup("apple").unwrap().kind, IdpKind::Oidc);
        assert_eq!(lookup("github").unwrap().kind, IdpKind::GitHub);
    }

    #[test]
    fn unknown_preset_is_none() {
        assert!(lookup("facebook").is_none());
        assert!(lookup("").is_none());
    }

    #[test]
    fn google_defaults_include_openid_scope() {
        let p = lookup("google").expect("preset");
        assert!(p.default_scopes.contains(&"openid"));
        assert_eq!(p.issuer, "https://accounts.google.com");
        assert!(p.jwks_uri.is_some());
    }

    #[test]
    fn github_has_no_jwks() {
        let p = lookup("github").expect("preset");
        assert!(p.jwks_uri.is_none());
        assert!(p.default_scopes.contains(&"read:user"));
    }

    #[test]
    fn apple_has_no_userinfo_endpoint() {
        let p = lookup("apple").expect("preset");
        assert!(p.userinfo_endpoint.is_none());
    }

    #[test]
    fn microsoft_points_at_v2_endpoints() {
        let p = lookup("microsoft").expect("preset");
        assert!(p.authorization_endpoint.contains("/v2.0/authorize"));
        assert!(p.token_endpoint.contains("/v2.0/token"));
    }
}
