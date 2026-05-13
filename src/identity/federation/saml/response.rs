//! `<Response>` and `<Assertion>` XML construction, parsing, and validation.

use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::BTreeMap;

use super::authn_request::{format_xsd_datetime, parse_xsd_datetime};
use super::xml::{attr, escape_attr, escape_text, is_element, ns, parse_err};
use crate::core::Timestamp;
use crate::identity::error::IdentityError;

/// Parsed `<Assertion>` contents relevant to the consuming SP.
#[derive(Debug, Clone)]
pub struct Assertion {
    pub id: String,
    pub issuer: String,
    pub subject_name_id: Option<String>,
    pub subject_name_id_format: Option<String>,
    pub not_before: Option<Timestamp>,
    pub not_on_or_after: Option<Timestamp>,
    pub audience: Option<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
    pub in_response_to: Option<String>,
    pub session_index: Option<String>,
    pub destination: Option<String>,
}

/// Parsed `<Response>` structure.
#[derive(Debug, Clone)]
pub struct SamlResponse {
    pub id: String,
    pub in_response_to: Option<String>,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub issuer: String,
    pub status_code: String,
    pub assertions: Vec<Assertion>,
}

/// Builder for an IdP-issued `<Response>` with a single `<Assertion>`.
pub struct ResponseBuilder<'a> {
    pub response_id: &'a str,
    pub in_response_to: Option<&'a str>,
    pub issue_instant: Timestamp,
    pub destination: &'a str,
    pub issuer: &'a str,
    pub audience: &'a str,
    pub assertion_id: &'a str,
    pub subject_name_id: &'a str,
    pub subject_name_id_format: &'a str,
    pub session_index: &'a str,
    pub not_before: Timestamp,
    pub not_on_or_after: Timestamp,
    pub attributes: &'a BTreeMap<String, Vec<String>>,
}

/// Builds the XML for an IdP-issued `<Response>` with one `<Assertion>`.
/// Neither element is signed; signing is performed separately via the
/// `signature` module.
#[must_use]
pub fn build_response_xml(b: &ResponseBuilder<'_>) -> String {
    let mut attrs_xml = String::new();
    for (name, values) in b.attributes {
        attrs_xml.push_str(&format!(
            r#"<saml:Attribute Name="{n}">"#,
            n = escape_attr(name)
        ));
        for v in values {
            attrs_xml.push_str(&format!(
                r"<saml:AttributeValue>{v}</saml:AttributeValue>",
                v = escape_text(v)
            ));
        }
        attrs_xml.push_str("</saml:Attribute>");
    }
    let attrs_block = if attrs_xml.is_empty() {
        String::new()
    } else {
        format!("<saml:AttributeStatement>{attrs_xml}</saml:AttributeStatement>")
    };

    let in_response = b
        .in_response_to
        .map(|v| format!(r#" InResponseTo="{}""#, escape_attr(v)))
        .unwrap_or_default();
    let subj_in_response = b
        .in_response_to
        .map(|v| format!(r#" InResponseTo="{}""#, escape_attr(v)))
        .unwrap_or_default();

    let ts_resp = format_xsd_datetime(b.issue_instant);
    let ts_nb = format_xsd_datetime(b.not_before);
    let ts_noa = format_xsd_datetime(b.not_on_or_after);

    format!(
        r#"<samlp:Response xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{rid}" Version="2.0" IssueInstant="{ts}" Destination="{dest}"{inrt}><saml:Issuer>{iss}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status><saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{ts}"><saml:Issuer>{iss}</saml:Issuer><saml:Subject><saml:NameID Format="{nidf}">{nid}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{noa}" Recipient="{dest}"{subj_in}></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{ts}" SessionIndex="{sidx}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>{attrs}</saml:Assertion></samlp:Response>"#,
        samlp = ns::SAMLP,
        saml = ns::SAML,
        rid = escape_attr(b.response_id),
        ts = escape_attr(&ts_resp),
        dest = escape_attr(b.destination),
        inrt = in_response,
        iss = escape_text(b.issuer),
        aid = escape_attr(b.assertion_id),
        nidf = escape_attr(b.subject_name_id_format),
        nid = escape_text(b.subject_name_id),
        noa = escape_attr(&ts_noa),
        nb = escape_attr(&ts_nb),
        subj_in = subj_in_response,
        aud = escape_text(b.audience),
        sidx = escape_attr(b.session_index),
        attrs = attrs_block,
    )
}

/// Parses a SAML `<Response>` and its `<Assertion>` children.
pub fn parse_response(xml: &[u8]) -> Result<SamlResponse, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut buf = Vec::new();
    let mut response_id: Option<String> = None;
    let mut in_response_to: Option<String> = None;
    let mut issue_instant: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut response_issuer: Option<String> = None;
    let mut status_code: Option<String> = None;
    let mut assertions: Vec<Assertion> = Vec::new();

    let mut state = ParseState::Root;
    let mut current: Option<Assertion> = None;
    let mut attr_name: Option<String> = None;
    let mut attr_values: Vec<String> = Vec::new();
    let mut capturing_text: Option<TextTarget> = None;

    loop {
        let ev = reader.read_event_into(&mut buf);
        match ev {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                if is_element(e, ns::SAMLP, "Response") {
                    response_id = attr(e, "ID");
                    in_response_to = attr(e, "InResponseTo");
                    issue_instant = attr(e, "IssueInstant");
                    destination = attr(e, "Destination");
                } else if is_element(e, ns::SAMLP, "StatusCode") && state == ParseState::Status {
                    status_code = attr(e, "Value");
                } else if is_element(e, ns::SAMLP, "Status") {
                    state = ParseState::Status;
                } else if is_element(e, ns::SAML, "Assertion") {
                    current = Some(Assertion {
                        id: attr(e, "ID").unwrap_or_default(),
                        issuer: String::new(),
                        subject_name_id: None,
                        subject_name_id_format: None,
                        not_before: None,
                        not_on_or_after: None,
                        audience: None,
                        attributes: BTreeMap::new(),
                        in_response_to: in_response_to.clone(),
                        session_index: None,
                        destination: destination.clone(),
                    });
                    state = ParseState::Assertion;
                } else if is_element(e, ns::SAML, "Issuer") {
                    capturing_text = Some(if matches!(state, ParseState::Assertion) {
                        TextTarget::AssertionIssuer
                    } else {
                        TextTarget::ResponseIssuer
                    });
                } else if is_element(e, ns::SAML, "NameID") {
                    if let Some(ref mut a) = current {
                        a.subject_name_id_format = attr(e, "Format");
                    }
                    capturing_text = Some(TextTarget::SubjectNameId);
                } else if is_element(e, ns::SAML, "Conditions") {
                    if let Some(ref mut a) = current {
                        a.not_before = attr(e, "NotBefore").and_then(|s| parse_xsd_datetime(&s));
                        a.not_on_or_after =
                            attr(e, "NotOnOrAfter").and_then(|s| parse_xsd_datetime(&s));
                    }
                } else if is_element(e, ns::SAML, "Audience") {
                    capturing_text = Some(TextTarget::Audience);
                } else if is_element(e, ns::SAML, "AuthnStatement") {
                    if let Some(ref mut a) = current {
                        a.session_index = attr(e, "SessionIndex");
                    }
                } else if is_element(e, ns::SAML, "Attribute") {
                    attr_name = attr(e, "Name");
                    attr_values.clear();
                } else if is_element(e, ns::SAML, "AttributeValue") {
                    capturing_text = Some(TextTarget::AttributeValue);
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(target) = capturing_text.take() {
                    let val = t.unescape().map(|s| s.into_owned()).unwrap_or_default();
                    match target {
                        TextTarget::ResponseIssuer => response_issuer = Some(val),
                        TextTarget::AssertionIssuer => {
                            if let Some(ref mut a) = current {
                                a.issuer = val;
                            }
                        }
                        TextTarget::SubjectNameId => {
                            if let Some(ref mut a) = current {
                                a.subject_name_id = Some(val);
                            }
                        }
                        TextTarget::Audience => {
                            if let Some(ref mut a) = current {
                                a.audience = Some(val);
                            }
                        }
                        TextTarget::AttributeValue => attr_values.push(val),
                    }
                }
            }
            Ok(Event::End(e)) => {
                let nm = e.name();
                let name_bytes = nm.as_ref();
                if name_bytes.ends_with(b":Attribute") || name_bytes == b"Attribute" {
                    if let (Some(n), Some(a)) = (attr_name.take(), current.as_mut()) {
                        if !attr_values.is_empty() {
                            a.attributes.insert(n, std::mem::take(&mut attr_values));
                        }
                    }
                } else if name_bytes.ends_with(b":Assertion") || name_bytes == b"Assertion" {
                    if let Some(a) = current.take() {
                        assertions.push(a);
                    }
                    state = ParseState::Root;
                } else if name_bytes.ends_with(b":Status") || name_bytes == b"Status" {
                    state = ParseState::Root;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(parse_err(format!("Response parse error: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    Ok(SamlResponse {
        id: response_id.ok_or_else(|| parse_err("Response missing ID"))?,
        in_response_to,
        issue_instant: issue_instant.ok_or_else(|| parse_err("missing IssueInstant"))?,
        destination,
        issuer: response_issuer.unwrap_or_default(),
        status_code: status_code.ok_or_else(|| parse_err("missing StatusCode"))?,
        assertions,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Root,
    Status,
    Assertion,
}

#[derive(Debug, Clone, Copy)]
enum TextTarget {
    ResponseIssuer,
    AssertionIssuer,
    SubjectNameId,
    Audience,
    AttributeValue,
}

/// Validates a SAML `<Response>` + `<Assertion>` for an SP.
///
/// Returns the assertion on success. Caller should have already verified
/// XML-DSIG signatures on the signed element before calling this.
pub struct ValidateParams<'a> {
    /// This SP's entity ID.
    pub sp_entity_id: &'a str,
    /// The ACS URL; must match `Destination`.
    pub acs_url: &'a str,
    /// Expected IdP entity ID.
    pub idp_entity_id: &'a str,
    /// Expected `InResponseTo` (the AuthnRequest ID we issued), or None
    /// for IdP-initiated SSO.
    pub expected_in_response_to: Option<&'a str>,
    /// Current time.
    pub now: Timestamp,
    /// Clock-skew tolerance in seconds.
    pub clock_skew_secs: i64,
}

/// Validates and extracts a single assertion from a parsed response.
///
/// On success returns the assertion. The caller is responsible for the
/// replay check (the assertion ID must not be reused) — this is done
/// externally against storage.
pub fn extract_and_validate_assertion(
    resp: &SamlResponse,
    p: &ValidateParams<'_>,
) -> Result<Assertion, IdentityError> {
    // Status must be Success.
    if !resp.status_code.ends_with("status:Success") {
        return Err(IdentityError::SamlInvalidAuthnRequest {
            reason: format!("non-success status: {}", resp.status_code),
        });
    }

    if resp.assertions.is_empty() {
        return Err(parse_err("no assertions in Response"));
    }
    if resp.assertions.len() > 1 {
        return Err(parse_err("multiple assertions not supported"));
    }
    let a = resp.assertions[0].clone();

    // Destination check (on the Response element).
    if let Some(ref d) = resp.destination {
        if d != p.acs_url {
            return Err(IdentityError::SamlDestinationMismatch);
        }
    }

    // Issuer check.
    if a.issuer != p.idp_entity_id && resp.issuer != p.idp_entity_id {
        return Err(IdentityError::SamlIssuerMismatch);
    }

    // Audience check.
    match &a.audience {
        Some(v) if v == p.sp_entity_id => {}
        _ => return Err(IdentityError::SamlAudienceMismatch),
    }

    // Timestamps.
    let now_micros = p.now.as_micros();
    let skew = p.clock_skew_secs * 1_000_000;
    if let Some(nb) = a.not_before {
        if nb.as_micros() > now_micros + skew {
            return Err(IdentityError::SamlExpired);
        }
    }
    if let Some(noa) = a.not_on_or_after {
        if noa.as_micros() <= now_micros - skew {
            return Err(IdentityError::SamlExpired);
        }
    }

    // InResponseTo.
    if let Some(expected) = p.expected_in_response_to {
        match &resp.in_response_to {
            Some(got) if got == expected => {}
            _ => {
                return Err(IdentityError::SamlInvalidAuthnRequest {
                    reason: "InResponseTo mismatch".to_string(),
                })
            }
        }
    }

    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_builder() -> ResponseBuilder<'static> {
        static AUD: &str = "https://sp.example";
        let attrs: &'static BTreeMap<String, Vec<String>> = Box::leak(Box::default());
        ResponseBuilder {
            response_id: "_r1",
            in_response_to: Some("_req1"),
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            destination: "https://sp.example/acs",
            issuer: "https://idp.example",
            audience: AUD,
            assertion_id: "_a1",
            subject_name_id: "alice@example.com",
            subject_name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index: "sess1",
            not_before: Timestamp::from_micros(1_699_999_990 * 1_000_000),
            not_on_or_after: Timestamp::from_micros(1_700_000_300 * 1_000_000),
            attributes: attrs,
        }
    }

    #[test]
    fn build_parse_roundtrip() {
        let xml = build_response_xml(&sample_builder());
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.id, "_r1");
        assert_eq!(parsed.assertions.len(), 1);
        let a = &parsed.assertions[0];
        assert_eq!(a.id, "_a1");
        assert_eq!(a.subject_name_id.as_deref(), Some("alice@example.com"));
        assert_eq!(a.audience.as_deref(), Some("https://sp.example"));
    }

    #[test]
    fn validate_audience_mismatch() {
        let xml = build_response_xml(&sample_builder());
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        let res = extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: "https://OTHER.example",
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to: None,
                now: Timestamp::from_micros(1_700_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        );
        assert!(matches!(res, Err(IdentityError::SamlAudienceMismatch)));
    }

    #[test]
    fn validate_expired_rejected() {
        let xml = build_response_xml(&sample_builder());
        let parsed = parse_response(xml.as_bytes()).expect("parse");
        let res = extract_and_validate_assertion(
            &parsed,
            &ValidateParams {
                sp_entity_id: "https://sp.example",
                acs_url: "https://sp.example/acs",
                idp_entity_id: "https://idp.example",
                expected_in_response_to: None,
                now: Timestamp::from_micros(1_800_000_000 * 1_000_000),
                clock_skew_secs: 60,
            },
        );
        assert!(matches!(res, Err(IdentityError::SamlExpired)));
    }
}
