//! External IdP federation / social login.
//!
//! Hearth as an OIDC *relying party*. This module lets a realm declare
//! upstream Identity Providers (Google, Microsoft, Apple, GitHub, or
//! arbitrary OIDC-compliant issuers) that end users can sign in with.
//!
//! The module exposes:
//!
//! - [`types`] — pure domain types ([`IdpConfig`], [`IdpKind`],
//!   [`LinkMode`], [`StateBag`], [`ExternalIdentity`],
//!   [`ConfirmLinkTicket`]).
//! - [`http`] — injectable HTTP transport ([`FederationHttpTransport`]
//!   + `UreqFederationTransport` for prod + `StubFederationTransport`
//!   for tests).
//!
//! Downstream modules (coming in later checkpoints):
//!
//! - `connector` — [`IdpConnector`] trait + `IdpHandle` dispatch
//! - `oidc` — `GenericOidcConnector` covering all OIDC-compliant providers
//! - `github` — `GithubConnector` for OAuth2 quirks
//! - `presets` — `expand_preset` for `google` / `microsoft` / `apple`
//! - `service` — `FederationService` orchestrating begin/exchange/link
//!
//! Off the hot path entirely — federation callbacks are infrequent.

pub mod http;
pub mod types;

pub use http::{
    FedHttpRequest, FedHttpResponse, FederationHttpTransport, StubFederationTransport,
    StubResponse, UreqFederationTransport,
};
pub use types::{
    ConfirmLinkTicket, ExternalIdentity, FederationSecret, IdpConfig, IdpKind, LinkMode, StateBag,
};
