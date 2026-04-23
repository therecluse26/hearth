//! SAML metadata `<EntityDescriptor>` generation and parsing.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use quick_xml::events::Event;
use quick_xml::Reader;

use super::xml::{attr, escape_attr, is_element, ns, parse_err, read_text};
use crate::identity::error::IdentityError;

/// SP metadata parameters.
pub struct SpMetadataParams<'a> {
    /// SP's own entity ID (typically the realm's base URL).
    pub entity_id: &'a str,
    /// Hearth ACS URL where signed Responses are delivered.
    pub acs_url: &'a str,
    /// Hearth SLO URL (optional).
    pub slo_url: Option<&'a str>,
    /// Whether outbound AuthnRequests will be signed.
    pub sign_authn_requests: bool,
    /// Whether Hearth requires signed assertions from the IdP.
    pub want_assertions_signed: bool,
    /// Optional signing certificate DER to embed for signing requests.
    pub signing_cert_der: Option<&'a [u8]>,
}

/// Builds an `<EntityDescriptor>` XML document for an SP.
#[must_use]
pub fn build_sp_metadata(p: &SpMetadataParams<'_>) -> String {
    let key_desc = p
        .signing_cert_der
        .map(|der| {
            let b64 = B64.encode(der);
            format!(
                r#"<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{ds}"><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#,
                ds = ns::DS,
                cert = b64,
            )
        })
        .unwrap_or_default();

    let slo = p
        .slo_url
        .map(|u| {
            format!(
                r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{loc}"></md:SingleLogoutService>"#,
                loc = escape_attr(u)
            )
        })
        .unwrap_or_default();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="{md}" entityID="{eid}"><md:SPSSODescriptor AuthnRequestsSigned="{ars}" WantAssertionsSigned="{was}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{key}{slo}<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0" isDefault="true"></md:AssertionConsumerService></md:SPSSODescriptor></md:EntityDescriptor>"#,
        md = ns::MD,
        eid = escape_attr(p.entity_id),
        ars = p.sign_authn_requests,
        was = p.want_assertions_signed,
        key = key_desc,
        slo = slo,
        acs = escape_attr(p.acs_url),
    )
}

/// IdP metadata parameters.
pub struct IdpMetadataParams<'a> {
    pub entity_id: &'a str,
    pub sso_url: &'a str,
    pub slo_url: Option<&'a str>,
    pub signing_cert_der: &'a [u8],
}

/// Builds an `<EntityDescriptor>` for Hearth acting as an IdP.
#[must_use]
pub fn build_idp_metadata(p: &IdpMetadataParams<'_>) -> String {
    let cert_b64 = B64.encode(p.signing_cert_der);
    let slo_redirect = p
        .slo_url
        .map(|u| {
            format!(
                r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{loc}"></md:SingleLogoutService>"#,
                loc = escape_attr(u)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="{md}" entityID="{eid}"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{ds}"><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>{slo}<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso}"></md:SingleSignOnService><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso}"></md:SingleSignOnService></md:IDPSSODescriptor></md:EntityDescriptor>"#,
        md = ns::MD,
        ds = ns::DS,
        eid = escape_attr(p.entity_id),
        cert = cert_b64,
        slo = slo_redirect,
        sso = escape_attr(p.sso_url),
    )
}

/// Parsed IdP metadata relevant for SP-side configuration.
#[derive(Debug, Clone)]
pub struct ParsedIdpMetadata {
    pub entity_id: String,
    pub sso_redirect_url: Option<String>,
    pub sso_post_url: Option<String>,
    pub slo_url: Option<String>,
    /// Signing certificate(s) in PEM format.
    pub signing_certs_pem: Vec<String>,
}

/// Parses an `<EntityDescriptor>` containing an `<IDPSSODescriptor>`.
pub fn parse_idp_metadata(xml: &[u8]) -> Result<ParsedIdpMetadata, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut entity_id: Option<String> = None;
    let mut sso_redirect: Option<String> = None;
    let mut sso_post: Option<String> = None;
    let mut slo_url: Option<String> = None;
    let mut certs: Vec<String> = Vec::new();
    let mut in_idp = false;
    let mut expect_cert = false;

    let mut buf = Vec::new();
    loop {
        let ev = reader.read_event_into(&mut buf);
        match ev {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                if is_element(e, ns::MD, "EntityDescriptor") && entity_id.is_none() {
                    entity_id = attr(e, "entityID");
                } else if is_element(e, ns::MD, "IDPSSODescriptor") {
                    in_idp = true;
                } else if in_idp && is_element(e, ns::MD, "SingleSignOnService") {
                    let binding = attr(e, "Binding").unwrap_or_default();
                    let loc = attr(e, "Location");
                    if binding.ends_with("HTTP-Redirect") {
                        sso_redirect = loc;
                    } else if binding.ends_with("HTTP-POST") {
                        sso_post = loc;
                    }
                } else if in_idp && is_element(e, ns::MD, "SingleLogoutService") {
                    if slo_url.is_none() {
                        slo_url = attr(e, "Location");
                    }
                } else if in_idp && e.name().as_ref().ends_with(b"X509Certificate") {
                    expect_cert = true;
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref().ends_with(b"IDPSSODescriptor") {
                    in_idp = false;
                }
            }
            Ok(Event::Text(t)) if expect_cert => {
                if let Ok(s) = t.unescape() {
                    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
                    if !cleaned.is_empty() {
                        certs.push(wrap_cert_pem(&cleaned));
                    }
                }
                expect_cert = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(parse_err(format!("metadata parse error: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    let entity_id = entity_id.ok_or_else(|| parse_err("no entityID in metadata"))?;

    Ok(ParsedIdpMetadata {
        entity_id,
        sso_redirect_url: sso_redirect,
        sso_post_url: sso_post,
        slo_url,
        signing_certs_pem: certs,
    })
}

fn wrap_cert_pem(b64: &str) -> String {
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

// Unused for compatibility with other modules expecting `read_text`.
#[allow(dead_code)]
fn _read_text_unused<R: std::io::BufRead>(r: &mut Reader<R>) -> Result<String, IdentityError> {
    read_text(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sp_metadata_contains_acs() {
        let p = SpMetadataParams {
            entity_id: "https://hearth.example/acme",
            acs_url: "https://hearth.example/ui/realms/acme/federation/saml/acs",
            slo_url: None,
            sign_authn_requests: false,
            want_assertions_signed: true,
            signing_cert_der: None,
        };
        let xml = build_sp_metadata(&p);
        assert!(xml.contains("AssertionConsumerService"));
        assert!(xml.contains("https://hearth.example/ui/realms/acme/federation/saml/acs"));
    }

    #[test]
    fn idp_metadata_includes_cert_and_sso() {
        let p = IdpMetadataParams {
            entity_id: "https://hearth.example/realms/acme",
            sso_url: "https://hearth.example/ui/realms/acme/saml/sso",
            slo_url: Some("https://hearth.example/ui/realms/acme/saml/slo-idp"),
            signing_cert_der: b"fake-cert-bytes",
        };
        let xml = build_idp_metadata(&p);
        assert!(xml.contains("IDPSSODescriptor"));
        assert!(xml.contains("SingleSignOnService"));
        assert!(xml.contains("X509Certificate"));
    }

    #[test]
    fn parses_own_idp_metadata() {
        let xml = build_idp_metadata(&IdpMetadataParams {
            entity_id: "https://idp.example",
            sso_url: "https://idp.example/sso",
            slo_url: Some("https://idp.example/slo"),
            signing_cert_der: b"\x01\x02\x03\x04",
        });
        let parsed = parse_idp_metadata(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.entity_id, "https://idp.example");
        assert_eq!(
            parsed.sso_redirect_url.as_deref(),
            Some("https://idp.example/sso")
        );
        assert!(parsed.signing_certs_pem.len() == 1);
    }
}
