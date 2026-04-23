//! `<AuthnRequest>` XML construction and parsing.

use quick_xml::events::Event;
use quick_xml::Reader;

use super::xml::{attr, escape_attr, is_element, ns, parse_err};
use crate::core::Timestamp;
use crate::identity::error::IdentityError;

/// An AuthnRequest after parsing.
#[derive(Debug, Clone)]
pub struct AuthnRequest {
    pub id: String,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub issuer: String,
    pub assertion_consumer_service_url: Option<String>,
    pub protocol_binding: Option<String>,
    pub nameid_format: Option<String>,
}

/// Parameters for building an AuthnRequest.
pub struct BuildAuthnRequestParams<'a> {
    /// Unique request ID (format: `_` + hex/base62). SAML requires the
    /// ID to start with a letter or `_`.
    pub id: &'a str,
    /// Destination (the IdP's SSO URL).
    pub destination: &'a str,
    /// Issuer (SP's entity ID).
    pub issuer: &'a str,
    /// The ACS URL where the response will be POSTed.
    pub acs_url: &'a str,
    /// Issue instant (serialized via `Timestamp`).
    pub issue_instant: Timestamp,
    /// Optional NameIDPolicy format hint.
    pub nameid_format: Option<&'a str>,
    /// If true, request forced re-authentication.
    pub force_authn: bool,
}

/// Builds a SAML `<AuthnRequest>` XML document.
#[must_use]
pub fn build_authn_request_xml(p: &BuildAuthnRequestParams<'_>) -> String {
    let nameid = p
        .nameid_format
        .map(|f| {
            format!(
                r#"<samlp:NameIDPolicy AllowCreate="true" Format="{f}"></samlp:NameIDPolicy>"#,
                f = escape_attr(f)
            )
        })
        .unwrap_or_default();
    let force = if p.force_authn { "true" } else { "false" };
    let iso_ts = format_xsd_datetime(p.issue_instant);
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{id}" Version="2.0" IssueInstant="{ts}" Destination="{dest}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs}" ForceAuthn="{fa}"><saml:Issuer>{iss}</saml:Issuer>{nid}</samlp:AuthnRequest>"#,
        samlp = ns::SAMLP,
        saml = ns::SAML,
        id = escape_attr(p.id),
        ts = escape_attr(&iso_ts),
        dest = escape_attr(p.destination),
        acs = escape_attr(p.acs_url),
        fa = force,
        iss = super::xml::escape_text(p.issuer),
        nid = nameid,
    )
}

/// Parses a SAML `<AuthnRequest>`.
pub fn parse_authn_request(xml: &[u8]) -> Result<AuthnRequest, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut id: Option<String> = None;
    let mut issue_instant: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut acs: Option<String> = None;
    let mut binding: Option<String> = None;
    let mut nameid: Option<String> = None;
    let mut in_issuer = false;

    let mut buf = Vec::new();
    loop {
        let ev = reader.read_event_into(&mut buf);
        match ev {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                if is_element(e, ns::SAMLP, "AuthnRequest") {
                    id = attr(e, "ID");
                    issue_instant = attr(e, "IssueInstant");
                    destination = attr(e, "Destination");
                    acs = attr(e, "AssertionConsumerServiceURL");
                    binding = attr(e, "ProtocolBinding");
                } else if is_element(e, ns::SAMLP, "NameIDPolicy") {
                    nameid = attr(e, "Format");
                } else if is_element(e, ns::SAML, "Issuer") {
                    in_issuer = true;
                }
            }
            Ok(Event::Text(t)) if in_issuer => {
                if let Ok(s) = t.unescape() {
                    issuer = Some(s.into_owned());
                }
                in_issuer = false;
            }
            Ok(Event::End(_)) => {
                in_issuer = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(parse_err(format!("AuthnRequest parse: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    Ok(AuthnRequest {
        id: id.ok_or_else(|| parse_err("AuthnRequest missing ID"))?,
        issue_instant: issue_instant.ok_or_else(|| parse_err("missing IssueInstant"))?,
        destination,
        issuer: issuer.ok_or_else(|| parse_err("AuthnRequest missing Issuer"))?,
        assertion_consumer_service_url: acs,
        protocol_binding: binding,
        nameid_format: nameid,
    })
}

/// Formats a timestamp in XSD `dateTime` format (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_xsd_datetime(ts: Timestamp) -> String {
    use time::format_description::well_known::Iso8601;
    let odt = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ts.as_micros()) * 1000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    odt.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Parses an XSD `dateTime` string back to `Timestamp`.
pub fn parse_xsd_datetime(s: &str) -> Option<Timestamp> {
    use time::format_description::well_known::Iso8601;
    let odt = time::OffsetDateTime::parse(s, &Iso8601::DEFAULT).ok()?;
    let nanos = odt.unix_timestamp_nanos();
    let micros = (nanos / 1000) as i64;
    Some(Timestamp::from_micros(micros))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_roundtrip() {
        let xml = build_authn_request_xml(&BuildAuthnRequestParams {
            id: "_abc123",
            destination: "https://idp.example/sso",
            issuer: "https://sp.example",
            acs_url: "https://sp.example/acs",
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            nameid_format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            force_authn: false,
        });
        let parsed = parse_authn_request(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.id, "_abc123");
        assert_eq!(
            parsed.destination.as_deref(),
            Some("https://idp.example/sso")
        );
        assert_eq!(parsed.issuer, "https://sp.example");
        assert_eq!(
            parsed.assertion_consumer_service_url.as_deref(),
            Some("https://sp.example/acs")
        );
    }
}
