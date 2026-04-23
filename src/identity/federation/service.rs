//! `FederationService` — connector registry + orchestration of
//! `begin` / `callback` / `link` for external IdP logins.
//!
//! The service holds no mutable state of its own — it is a façade over
//! the injected `Arc<dyn IdentityEngine>` (for storage / engine state)
//! plus the shared `Arc<dyn FederationHttpTransport>` (for outbound HTTP).
//!
//! Connectors are loaded lazily on each call — there is no in-memory
//! cache of IdpConfig. Config changes via YAML reconcile take effect
//! immediately on the next login attempt. For v1 this is plenty fast
//! (callback is off the hot path).

use std::sync::Arc;

use crate::core::{IdpId, RealmId, Timestamp, UserId};
use crate::identity::federation::connector::{AuthorizeUrl, IdpConnector};
use crate::identity::federation::github::GithubConnector;
use crate::identity::federation::http::FederationHttpTransport;
use crate::identity::federation::oidc::GenericOidcConnector;
use crate::identity::federation::state::{
    generate_nonce, generate_pkce_verifier, generate_state_token,
};
use crate::identity::federation::types::{
    ConfirmLinkTicket, ExternalIdentity, IdpConfig, IdpKind, LinkMode, StateBag,
};
use crate::identity::{IdentityEngine, IdentityError};

/// How long an in-flight federation state lives. Browser round-trip
/// plus user consent at the upstream fits comfortably in 10 minutes.
const FED_STATE_TTL_MICROS: i64 = 10 * 60 * 1_000_000;

/// How long a confirm-to-link ticket lives.
const FED_CONFIRM_TTL_MICROS: i64 = 10 * 60 * 1_000_000;

/// Orchestrates federation login.
#[derive(Clone)]
pub struct FederationService {
    engine: Arc<dyn IdentityEngine>,
    http: Arc<dyn FederationHttpTransport>,
    /// Absolute redirect URI registered at upstream IdPs.
    redirect_uri: String,
}

/// What a successful federation callback produces.
#[derive(Debug)]
pub enum FederationOutcome {
    /// The external identity is already linked to this user — log them in.
    ExistingUser(UserId),
    /// The external identity is not linked and no matching local email
    /// exists — caller should JIT-provision a new user, then call
    /// [`FederationService::after_jit_provision`].
    JitProvision(ExternalIdentity),
    /// The external identity matched an existing user under
    /// `LinkMode::Confirm`. The ticket must be persisted in a HMAC-bound
    /// cookie (see [`super::state::compute_confirm_ticket_mac`]) and the
    /// user redirected to `/ui/federation/confirm-link`.
    ConfirmLinkRequired(ConfirmLinkTicket),
    /// Under `LinkMode::Auto`, the external identity was silently linked
    /// to an existing user on the fly.
    AutoLinked(UserId),
}

impl FederationService {
    /// Creates a new service.
    pub fn new(
        engine: Arc<dyn IdentityEngine>,
        http: Arc<dyn FederationHttpTransport>,
        redirect_uri: String,
    ) -> Self {
        Self {
            engine,
            http,
            redirect_uri,
        }
    }

    /// Returns the callback URL this service expects upstreams to
    /// redirect back to.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Builds and persists a state bag, returning the authorize URL
    /// to redirect the browser to.
    pub fn begin(
        &self,
        realm_id: &RealmId,
        idp_name: &str,
        return_to: &str,
        now: Timestamp,
    ) -> Result<AuthorizeUrl, IdentityError> {
        let cfg = self
            .engine
            .get_idp_by_name(realm_id, idp_name)?
            .ok_or(IdentityError::FederationUnknownConnector)?;

        let bag = StateBag {
            state_token: generate_state_token()?,
            realm_id: cfg.realm_id.clone(),
            idp_id: cfg.id.clone(),
            nonce: generate_nonce()?,
            pkce_verifier: generate_pkce_verifier()?,
            return_to: return_to.to_string(),
            expires_at: Timestamp::from_micros(now.as_micros() + FED_STATE_TTL_MICROS),
        };
        self.engine.put_federation_state(&bag)?;
        self.connector_for(&cfg)?.begin(&bag)
    }

    /// Completes a callback round-trip.
    ///
    /// Caller is responsible for:
    /// - Re-reading the state bag out of storage (validated here).
    /// - Looking up a local user by email if the returned outcome is
    ///   `JitProvision` or `ConfirmLinkRequired`.
    pub fn callback(
        &self,
        realm_id: &RealmId,
        state_token: &str,
        code: &str,
        link_mode: LinkMode,
        now: Timestamp,
    ) -> Result<(StateBag, FederationOutcome), IdentityError> {
        let bag = self.engine.take_federation_state(realm_id, state_token)?;
        let cfg = self
            .engine
            .get_idp(realm_id, &bag.idp_id)?
            .ok_or(IdentityError::FederationUnknownConnector)?;
        let identity = self.connector_for(&cfg)?.exchange(code, &bag)?;

        // 1. Existing link?
        if let Some(user_id) = self.engine.find_user_by_external_identity(
            realm_id,
            &identity.idp_id,
            &identity.external_sub,
        )? {
            return Ok((bag, FederationOutcome::ExistingUser(user_id)));
        }

        // 2. Email match → dispatch by LinkMode.
        if identity.is_linkable_by_email() {
            if let Some(existing) = self.engine.get_user_by_email(realm_id, &identity.email)? {
                match link_mode {
                    LinkMode::Disabled => {
                        // Fall through to JIT.
                    }
                    LinkMode::Auto => {
                        self.engine.link_external_identity(
                            realm_id,
                            existing.id(),
                            &identity.idp_id,
                            &identity.external_sub,
                        )?;
                        return Ok((bag, FederationOutcome::AutoLinked(existing.id().clone())));
                    }
                    LinkMode::Confirm => {
                        let ticket = ConfirmLinkTicket {
                            ticket: uuid::Uuid::new_v4().to_string(),
                            realm_id: realm_id.clone(),
                            user_id: existing.id().clone(),
                            identity: identity.clone(),
                            expires_at: Timestamp::from_micros(
                                now.as_micros() + FED_CONFIRM_TTL_MICROS,
                            ),
                        };
                        self.engine.put_confirm_link_ticket(&ticket)?;
                        return Ok((bag, FederationOutcome::ConfirmLinkRequired(ticket)));
                    }
                }
            }
        }

        // 3. No existing user / unverified email / link disabled → JIT.
        Ok((bag, FederationOutcome::JitProvision(identity)))
    }

    /// Called by the web handler after it has provisioned a fresh user
    /// for a JIT outcome — persists the external-identity link so the
    /// next login lands on the existing user.
    pub fn after_jit_provision(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        idp_id: &IdpId,
        external_sub: &str,
    ) -> Result<(), IdentityError> {
        self.engine
            .link_external_identity(realm_id, user_id, idp_id, external_sub)
    }

    /// Instantiates the right connector for a config.
    fn connector_for(&self, cfg: &IdpConfig) -> Result<Box<dyn IdpConnector>, IdentityError> {
        match cfg.kind {
            IdpKind::Oidc => Ok(Box::new(GenericOidcConnector::new(
                cfg.clone(),
                self.http.clone(),
                self.redirect_uri.clone(),
            ))),
            IdpKind::GitHub => Ok(Box::new(GithubConnector::new(
                cfg.clone(),
                self.http.clone(),
                self.redirect_uri.clone(),
            ))),
        }
    }
}
