//! SP-side orchestration: begin login, consume Response at ACS, SLO.
//!
//! Pure logic — no storage, no HTTP. Callers (engine, web handlers)
//! combine these primitives with their own state-stores.

use super::response::{extract_and_validate_assertion, parse_response, Assertion, ValidateParams};
use super::signature::verify_signed_element;
use super::types::{AttributeMap, SamlIdpConfig};
use super::xml::ns;
use crate::core::Timestamp;
use crate::identity::error::IdentityError;
use crate::identity::federation::types::ExternalIdentity;

/// Outcome of a completed SP login round-trip.
pub enum SamlSpOutcome {
    /// A valid assertion was accepted. The caller should proceed to
    /// federation's normal linking / JIT provisioning path.
    Accepted {
        /// Assertion metadata translated to the federation
        /// `ExternalIdentity` shape.
        identity: ExternalIdentity,
        /// Session index from the assertion's AuthnStatement (for SLO).
        session_index: Option<String>,
        /// The raw assertion (for audit / debugging).
        assertion: Assertion,
    },
    /// The response was rejected. `reason` is one of the SAML error
    /// variants; the engine maps this to a `SamlLoginFailed` audit event.
    Rejected { error: IdentityError },
}

/// Top-level SP service.
pub struct SamlSpService;

impl SamlSpService {
    /// Completes an SP-initiated login by validating a POSTed
    /// `SAMLResponse`.
    ///
    /// `xml` is the parsed+base64-decoded Response bytes.
    pub fn complete(
        idp: &SamlIdpConfig,
        sp_entity_id: &str,
        acs_url: &str,
        expected_in_response_to: Option<&str>,
        now: Timestamp,
        xml: &[u8],
    ) -> SamlSpOutcome {
        match Self::complete_inner(
            idp,
            sp_entity_id,
            acs_url,
            expected_in_response_to,
            now,
            xml,
        ) {
            Ok((identity, session_index, assertion)) => SamlSpOutcome::Accepted {
                identity,
                session_index,
                assertion,
            },
            Err(error) => SamlSpOutcome::Rejected { error },
        }
    }

    fn complete_inner(
        idp: &SamlIdpConfig,
        sp_entity_id: &str,
        acs_url: &str,
        expected_in_response_to: Option<&str>,
        now: Timestamp,
        xml: &[u8],
    ) -> Result<(ExternalIdentity, Option<String>, Assertion), IdentityError> {
        // Signature verification: prefer Assertion-level signature if
        // want_assertions_signed, else accept Response-level signature.
        let primary_cert = idp
            .idp_certificates_pem
            .first()
            .ok_or(IdentityError::SamlSignature)?;
        let mut sig_ok = false;
        if verify_signed_element(xml, "Assertion", primary_cert).is_ok() {
            sig_ok = true;
        }
        if !sig_ok {
            if idp.want_assertions_signed {
                return Err(IdentityError::SamlSignature);
            }
            // Fall back to Response-level signature.
            verify_signed_element(xml, "Response", primary_cert)?;
        }

        let resp = parse_response(xml)?;
        let assertion = extract_and_validate_assertion(
            &resp,
            &ValidateParams {
                sp_entity_id,
                acs_url,
                idp_entity_id: &idp.entity_id,
                expected_in_response_to,
                now,
                clock_skew_secs: 60,
            },
        )?;

        let identity =
            assertion_to_external_identity(idp.idp_id.clone(), &assertion, &idp.attribute_map)?;
        let session_index = assertion.session_index.clone();
        Ok((identity, session_index, assertion))
    }
}

/// Translates a parsed `<Assertion>` into an `ExternalIdentity` using the
/// configured attribute map.
fn assertion_to_external_identity(
    idp_id: crate::core::IdpId,
    a: &Assertion,
    map: &AttributeMap,
) -> Result<ExternalIdentity, IdentityError> {
    let nameid = a.subject_name_id.as_deref().unwrap_or("").to_string();

    let email = resolve(map, "email", a, &nameid).unwrap_or_else(|| nameid.clone());
    let display_name = resolve(map, "display_name", a, &nameid).unwrap_or_default();
    let first_name = resolve(map, "first_name", a, &nameid).unwrap_or_default();
    let last_name = resolve(map, "last_name", a, &nameid).unwrap_or_default();
    let external_sub = resolve(map, "external_sub", a, &nameid).unwrap_or_else(|| nameid.clone());

    Ok(ExternalIdentity {
        idp_id,
        external_sub,
        email,
        // SAML doesn't carry a `email_verified` signal; enterprises treat
        // SAML-asserted emails as trustworthy since they come from a
        // trusted corporate IdP. Still, default to false and require the
        // caller to opt into auto-link via YAML.
        email_verified: false,
        display_name,
        first_name,
        last_name,
        picture_url: None,
    })
}

fn resolve(map: &AttributeMap, field: &str, a: &Assertion, nameid: &str) -> Option<String> {
    let src = map.get(field)?;
    if src == "NameID" {
        return Some(nameid.to_string());
    }
    a.attributes
        .get(src)
        .and_then(|vs| vs.first())
        .map(|v| v.clone())
}

// Prevent unused-import warning on debug-only ns path.
#[allow(dead_code)]
const _SAML_NS: &str = ns::SAML;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_map_name_id_fallback() {
        use crate::core::IdpId;
        use std::collections::BTreeMap;
        let mut m = BTreeMap::new();
        m.insert("email".to_string(), "NameID".to_string());

        let a = Assertion {
            id: "a1".into(),
            issuer: "idp".into(),
            subject_name_id: Some("alice@example.com".into()),
            subject_name_id_format: None,
            not_before: None,
            not_on_or_after: None,
            audience: None,
            attributes: BTreeMap::new(),
            in_response_to: None,
            session_index: None,
            destination: None,
        };
        let ext = assertion_to_external_identity(IdpId::generate(), &a, &m).expect("map");
        assert_eq!(ext.email, "alice@example.com");
    }
}
