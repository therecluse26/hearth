//! The `IdpConnector` trait and its enum-dispatched handle.
//!
//! Every upstream IdP Hearth supports is one of two concrete connector
//! types (`GenericOidcConnector` or `GithubConnector`). Rather than a
//! trait object (which would force `async-trait` and heap allocation),
//! connectors sit behind an [`IdpHandle`] enum that the
//! `FederationService` matches on.
//!
//! This trait is the contract the service needs. Implementations live
//! in sibling modules: `oidc.rs`, `github.rs` (Checkpoint C).

use crate::identity::federation::types::{ExternalIdentity, IdpKind, StateBag};
use crate::identity::IdentityError;

/// The URL a connector's `begin()` produces.
///
/// Typed as a wrapper (rather than a bare `String`) so callers can't
/// accidentally swap it for a user-controlled URL — redirection to a
/// non-IdP origin is the primary attack on federation `begin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeUrl(pub String);

impl AuthorizeUrl {
    /// Returns the underlying URL string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The contract every concrete connector implements.
///
/// `begin()` builds the upstream authorize URL from a freshly-generated
/// [`StateBag`]. `exchange()` consumes the upstream `code` (post
/// browser round-trip) and returns a resolved [`ExternalIdentity`].
///
/// Both methods are synchronous: the federation callback path is
/// entirely off the hot path, and all I/O happens through the
/// injectable [`super::FederationHttpTransport`] which already uses
/// `block_in_place` for multi-thread Tokio runtimes. Making the trait
/// synchronous keeps it object-safe and avoids `async-trait` heap
/// allocations that CLAUDE.md forbids on the hot path.
pub trait IdpConnector: Send + Sync {
    /// The connector's protocol variant (used for audit events and
    /// for the `IdpHandle` dispatch enum).
    fn kind(&self) -> IdpKind;

    /// Returns the human-readable label for UI rendering.
    fn display_name(&self) -> &str;

    /// Builds the upstream authorize URL from an in-flight state bag.
    ///
    /// The caller is responsible for having persisted the bag under
    /// `fed:state:{token}` before redirecting the browser — the
    /// callback path relies on being able to retrieve the verifier
    /// and nonce by state token.
    fn begin(&self, state: &StateBag) -> Result<AuthorizeUrl, IdentityError>;

    /// Completes the upstream round trip.
    ///
    /// Exchanges `code` at the token endpoint using the PKCE verifier
    /// stored in `state`, verifies the ID token (OIDC) or fetches
    /// `/user` (OAuth2), and returns the resolved external identity.
    fn exchange(
        &self,
        code: &str,
        state: &StateBag,
    ) -> Result<ExternalIdentity, IdentityError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_round_trip() {
        let u = AuthorizeUrl("https://accounts.google.com/o/oauth2/v2/auth?...".to_string());
        assert!(u.as_str().starts_with("https://accounts.google.com"));
    }

    #[test]
    fn trait_is_object_safe() {
        // Allows `Arc<dyn IdpConnector>` if we ever want heterogeneous
        // collections — reserve the option without locking us into it.
        fn assert_object_safe(_: &dyn IdpConnector) {}
        struct Stub;
        impl IdpConnector for Stub {
            fn kind(&self) -> IdpKind {
                IdpKind::Oidc
            }
            fn display_name(&self) -> &str {
                "Stub"
            }
            fn begin(&self, _state: &StateBag) -> Result<AuthorizeUrl, IdentityError> {
                Ok(AuthorizeUrl("https://x".to_string()))
            }
            fn exchange(
                &self,
                _code: &str,
                _state: &StateBag,
            ) -> Result<ExternalIdentity, IdentityError> {
                unreachable!()
            }
        }
        assert_object_safe(&Stub);
    }
}
