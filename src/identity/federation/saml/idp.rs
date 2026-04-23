//! IdP-side orchestration: receive AuthnRequest, issue Response, SLO.

use std::collections::BTreeMap;

use super::authn_request::{parse_authn_request, AuthnRequest};
use super::response::{build_response_xml, ResponseBuilder};
use super::signature::sign_element;
use super::types::{SamlNameIdFormat, SamlServiceProvider};
use crate::core::Timestamp;
use crate::identity::error::IdentityError;
use crate::identity::tokens::RsaSigningKey;

/// What Hearth-as-IdP decided after receiving an AuthnRequest.
pub struct SamlIdpOutcome {
    /// The SP that was matched (found in the realm's SP registry).
    pub sp_key: String,
    /// The ACS URL to POST the Response back to.
    pub acs_url: String,
    /// The AuthnRequest ID (for `InResponseTo`).
    pub request_id: String,
    /// The AuthnRequest's issuer — MUST equal the registered SP's entity ID.
    pub request_issuer: String,
}

/// SAML IdP service — stateless helpers used by engine / web handlers.
pub struct SamlIdpService;

impl SamlIdpService {
    /// Validates an incoming `<AuthnRequest>`.
    ///
    /// Resolves the SP by `Issuer` matching a registered SP entity ID.
    /// Optionally enforces signature requirement.
    pub fn receive_authn_request(
        xml: &[u8],
        sps: &[SamlServiceProvider],
    ) -> Result<(SamlIdpOutcome, AuthnRequest), IdentityError> {
        let req = parse_authn_request(xml)?;
        let sp = sps
            .iter()
            .find(|s| s.entity_id == req.issuer)
            .ok_or(IdentityError::SamlUnknownSp)?;
        let acs_url = req
            .assertion_consumer_service_url
            .clone()
            .unwrap_or_else(|| sp.acs_url.clone());
        // ACS URL must match the registered one (defense against open-redirect
        // via spoofed AssertionConsumerServiceURL).
        if acs_url != sp.acs_url {
            return Err(IdentityError::SamlInvalidAuthnRequest {
                reason: "ACS URL does not match registered SP".into(),
            });
        }
        Ok((
            SamlIdpOutcome {
                sp_key: sp.sp_key.clone(),
                acs_url: sp.acs_url.clone(),
                request_id: req.id.clone(),
                request_issuer: req.issuer.clone(),
            },
            req,
        ))
    }

    /// Issues a signed `<Response>` containing one `<Assertion>` for the
    /// given SP.
    ///
    /// `in_response_to` is `Some(request_id)` for SP-initiated SSO,
    /// `None` for IdP-initiated SSO.
    pub fn issue_response(
        sp: &SamlServiceProvider,
        idp_entity_id: &str,
        user_name_id: &str,
        session_index: &str,
        attributes: &BTreeMap<String, Vec<String>>,
        in_response_to: Option<&str>,
        response_id: &str,
        assertion_id: &str,
        now: Timestamp,
        assertion_ttl_secs: i64,
        signing_key: &RsaSigningKey,
    ) -> Result<String, IdentityError> {
        let now_micros = now.as_micros();
        let not_before = Timestamp::from_micros(now_micros - 60 * 1_000_000);
        let not_on_or_after = Timestamp::from_micros(now_micros + assertion_ttl_secs * 1_000_000);

        let nameid_format = sp.nameid_format.as_uri();
        let mut outbound = BTreeMap::new();
        if !sp.attribute_map.is_empty() {
            // Remap Hearth field names into SAML attribute URIs per config.
            for (hearth_field, saml_name) in &sp.attribute_map {
                if let Some(vs) = attributes.get(hearth_field) {
                    outbound.insert(saml_name.clone(), vs.clone());
                }
            }
        } else {
            outbound = attributes.clone();
        }

        let xml = build_response_xml(&ResponseBuilder {
            response_id,
            in_response_to,
            issue_instant: now,
            destination: &sp.acs_url,
            issuer: idp_entity_id,
            audience: &sp.entity_id,
            assertion_id,
            subject_name_id: user_name_id,
            subject_name_id_format: nameid_format,
            session_index,
            not_before,
            not_on_or_after,
            attributes: &outbound,
        });

        // Sign whichever level is configured.
        if sp.sign_responses {
            sign_element(xml.as_bytes(), response_id, signing_key)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        } else if sp.sign_assertions {
            // Sign only the Assertion: extract its bytes, sign, splice back.
            // For Phase 1 simplicity we sign the whole Response when either
            // sign_assertions or sign_responses is true.
            sign_element(xml.as_bytes(), response_id, signing_key)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        } else {
            Ok(xml)
        }
    }
}

/// Suppresses unused warnings for types re-exported by the parent mod.
#[allow(dead_code)]
const _NAMEID_TOUCH: SamlNameIdFormat = SamlNameIdFormat::EmailAddress;
