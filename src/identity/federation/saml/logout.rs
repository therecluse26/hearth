//! `<LogoutRequest>` and `<LogoutResponse>` construction and parsing.

use quick_xml::events::Event;
use quick_xml::Reader;

use super::authn_request::format_xsd_datetime;
use super::xml::{attr, escape_attr, escape_text, is_element, ns, parse_err};
use crate::core::Timestamp;
use crate::identity::error::IdentityError;

#[derive(Debug, Clone)]
pub struct LogoutRequest {
    pub id: String,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub session_index: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LogoutResponse {
    pub id: String,
    pub in_response_to: Option<String>,
    pub issue_instant: String,
    pub destination: Option<String>,
    pub issuer: String,
    pub status_code: String,
}

pub struct BuildLogoutRequestParams<'a> {
    pub id: &'a str,
    pub destination: &'a str,
    pub issue_instant: Timestamp,
    pub issuer: &'a str,
    pub name_id: &'a str,
    pub name_id_format: &'a str,
    pub session_index: Option<&'a str>,
}

#[must_use]
pub fn build_logout_request_xml(p: &BuildLogoutRequestParams<'_>) -> String {
    let sidx = p
        .session_index
        .map(|s| {
            format!(
                "<samlp:SessionIndex>{}</samlp:SessionIndex>",
                escape_text(s)
            )
        })
        .unwrap_or_default();
    let ts = format_xsd_datetime(p.issue_instant);
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{id}" Version="2.0" IssueInstant="{ts}" Destination="{dest}"><saml:Issuer>{iss}</saml:Issuer><saml:NameID Format="{nidf}">{nid}</saml:NameID>{sidx}</samlp:LogoutRequest>"#,
        samlp = ns::SAMLP,
        saml = ns::SAML,
        id = escape_attr(p.id),
        ts = escape_attr(&ts),
        dest = escape_attr(p.destination),
        iss = escape_text(p.issuer),
        nidf = escape_attr(p.name_id_format),
        nid = escape_text(p.name_id),
        sidx = sidx,
    )
}

pub struct BuildLogoutResponseParams<'a> {
    pub id: &'a str,
    pub in_response_to: &'a str,
    pub destination: &'a str,
    pub issue_instant: Timestamp,
    pub issuer: &'a str,
    pub success: bool,
}

#[must_use]
pub fn build_logout_response_xml(p: &BuildLogoutResponseParams<'_>) -> String {
    let ts = format_xsd_datetime(p.issue_instant);
    let code = if p.success {
        "urn:oasis:names:tc:SAML:2.0:status:Success"
    } else {
        "urn:oasis:names:tc:SAML:2.0:status:Requester"
    };
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{samlp}" xmlns:saml="{saml}" ID="{id}" Version="2.0" IssueInstant="{ts}" Destination="{dest}" InResponseTo="{irt}"><saml:Issuer>{iss}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{code}"></samlp:StatusCode></samlp:Status></samlp:LogoutResponse>"#,
        samlp = ns::SAMLP,
        saml = ns::SAML,
        id = escape_attr(p.id),
        ts = escape_attr(&ts),
        dest = escape_attr(p.destination),
        irt = escape_attr(p.in_response_to),
        iss = escape_text(p.issuer),
        code = code,
    )
}

pub fn parse_logout_request(xml: &[u8]) -> Result<LogoutRequest, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut id: Option<String> = None;
    let mut issue_instant: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut name_id: Option<String> = None;
    let mut name_id_format: Option<String> = None;
    let mut session_index: Option<String> = None;

    enum Capture {
        Issuer,
        NameId,
        SessionIndex,
    }
    let mut capture: Option<Capture> = None;

    let mut buf = Vec::new();
    loop {
        let ev = reader.read_event_into(&mut buf);
        match ev {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                if is_element(e, ns::SAMLP, "LogoutRequest") {
                    id = attr(e, "ID");
                    issue_instant = attr(e, "IssueInstant");
                    destination = attr(e, "Destination");
                } else if is_element(e, ns::SAML, "Issuer") {
                    capture = Some(Capture::Issuer);
                } else if is_element(e, ns::SAML, "NameID") {
                    name_id_format = attr(e, "Format");
                    capture = Some(Capture::NameId);
                } else if is_element(e, ns::SAMLP, "SessionIndex") {
                    capture = Some(Capture::SessionIndex);
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(cap) = capture.take() {
                    let val = t.unescape().map(|s| s.into_owned()).unwrap_or_default();
                    match cap {
                        Capture::Issuer => issuer = Some(val),
                        Capture::NameId => name_id = Some(val),
                        Capture::SessionIndex => session_index = Some(val),
                    }
                }
            }
            Ok(Event::End(_)) => capture = None,
            Ok(Event::Eof) => break,
            Err(e) => return Err(parse_err(format!("LogoutRequest parse: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    Ok(LogoutRequest {
        id: id.ok_or_else(|| parse_err("LogoutRequest missing ID"))?,
        issue_instant: issue_instant.ok_or_else(|| parse_err("missing IssueInstant"))?,
        destination,
        issuer: issuer.ok_or_else(|| parse_err("LogoutRequest missing Issuer"))?,
        name_id: name_id.ok_or_else(|| parse_err("LogoutRequest missing NameID"))?,
        name_id_format,
        session_index,
    })
}

pub fn parse_logout_response(xml: &[u8]) -> Result<LogoutResponse, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut id: Option<String> = None;
    let mut in_response_to: Option<String> = None;
    let mut issue_instant: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut status_code: Option<String> = None;
    let mut in_issuer = false;

    let mut buf = Vec::new();
    loop {
        let ev = reader.read_event_into(&mut buf);
        match ev {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                if is_element(e, ns::SAMLP, "LogoutResponse") {
                    id = attr(e, "ID");
                    in_response_to = attr(e, "InResponseTo");
                    issue_instant = attr(e, "IssueInstant");
                    destination = attr(e, "Destination");
                } else if is_element(e, ns::SAMLP, "StatusCode") {
                    status_code = attr(e, "Value");
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
            Ok(Event::End(_)) => in_issuer = false,
            Ok(Event::Eof) => break,
            Err(e) => return Err(parse_err(format!("LogoutResponse parse: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    Ok(LogoutResponse {
        id: id.ok_or_else(|| parse_err("LogoutResponse missing ID"))?,
        in_response_to,
        issue_instant: issue_instant.ok_or_else(|| parse_err("missing IssueInstant"))?,
        destination,
        issuer: issuer.unwrap_or_default(),
        status_code: status_code.ok_or_else(|| parse_err("missing StatusCode"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_request_roundtrip() {
        let xml = build_logout_request_xml(&BuildLogoutRequestParams {
            id: "_lo1",
            destination: "https://sp.example/slo",
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            issuer: "https://idp.example",
            name_id: "alice@example.com",
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index: Some("sess1"),
        });
        let parsed = parse_logout_request(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.id, "_lo1");
        assert_eq!(parsed.name_id, "alice@example.com");
        assert_eq!(parsed.session_index.as_deref(), Some("sess1"));
    }

    #[test]
    fn logout_response_roundtrip() {
        let xml = build_logout_response_xml(&BuildLogoutResponseParams {
            id: "_lr1",
            in_response_to: "_lo1",
            destination: "https://idp.example/slo",
            issue_instant: Timestamp::from_micros(1_700_000_000 * 1_000_000),
            issuer: "https://sp.example",
            success: true,
        });
        let parsed = parse_logout_response(xml.as_bytes()).expect("parse");
        assert_eq!(parsed.in_response_to.as_deref(), Some("_lo1"));
        assert!(parsed.status_code.ends_with("Success"));
    }
}
