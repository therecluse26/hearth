//! HTTP-Redirect (DEFLATE + base64 + URL) and HTTP-POST bindings.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use flate2::write::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io::Write as _;

use super::xml::{escape_attr, parse_err};
use crate::identity::error::IdentityError;

/// Builds a fully-qualified redirect URL per SAML HTTP-Redirect binding.
///
/// `base` is the upstream SSO or SLO URL. `saml_xml` is the raw
/// `<AuthnRequest>` or `<LogoutRequest>` XML. `relay_state` is an
/// opaque echo token. Signature parameters are not included in this
/// minimal implementation — Hearth as SP sends unsigned redirect
/// requests (per config default). Signed redirect bindings require
/// URL-encoded signing of a specific parameter concatenation which we
/// leave as a later enhancement.
pub fn build_redirect_url(
    base: &str,
    param_name: &str,
    saml_xml: &[u8],
    relay_state: Option<&str>,
) -> Result<String, IdentityError> {
    // DEFLATE (raw, no zlib wrapper).
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(saml_xml)
        .map_err(|e| parse_err(format!("deflate: {e}")))?;
    let deflated = enc
        .finish()
        .map_err(|e| parse_err(format!("deflate finish: {e}")))?;
    let b64 = B64.encode(&deflated);
    let urlenc = url_encode(&b64);

    let sep = if base.contains('?') { '&' } else { '?' };
    let mut out = format!("{base}{sep}{param_name}={urlenc}");
    if let Some(rs) = relay_state {
        out.push_str("&RelayState=");
        out.push_str(&url_encode(rs));
    }
    Ok(out)
}

/// Decodes an inbound HTTP-Redirect request's `SAMLRequest` (or
/// `SAMLResponse`) parameter: URL-decode + base64 + DEFLATE.
pub fn decode_redirect_request(param_value: &str) -> Result<Vec<u8>, IdentityError> {
    let url_decoded = url_decode(param_value);
    let b64_decoded = B64
        .decode(url_decoded.as_slice())
        .map_err(|e| parse_err(format!("base64 decode: {e}")))?;
    let mut dec = DeflateDecoder::new(Vec::new());
    dec.write_all(&b64_decoded)
        .map_err(|e| parse_err(format!("inflate: {e}")))?;
    let inflated = dec
        .finish()
        .map_err(|e| parse_err(format!("inflate finish: {e}")))?;
    Ok(inflated)
}

/// Builds the HTML form-POST body per SAML HTTP-POST binding.
///
/// The browser loads this HTML and auto-submits the form to `action`,
/// carrying the SAML payload as `SAMLResponse` (or `SAMLRequest`) plus
/// a RelayState.
pub fn build_post_form_html(
    action: &str,
    param_name: &str,
    saml_xml: &[u8],
    relay_state: Option<&str>,
) -> String {
    let b64 = B64.encode(saml_xml);
    let relay = relay_state
        .map(|r| {
            format!(
                r#"<input type="hidden" name="RelayState" value="{}"/>"#,
                escape_attr(r)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html><html><head><title>SAML</title></head><body onload="document.forms[0].submit()"><noscript><p>JavaScript is required to complete the SAML flow. Submit the form below manually.</p></noscript><form method="POST" action="{action}"><input type="hidden" name="{param}" value="{payload}"/>{relay}<input type="submit" value="Continue"/></form></body></html>"#,
        action = escape_attr(action),
        param = param_name,
        payload = escape_attr(&b64),
        relay = relay,
    )
}

/// Decodes an inbound HTTP-POST form body SAML payload (base64 only,
/// no DEFLATE).
pub fn parse_post_form_saml(b64_value: &str) -> Result<Vec<u8>, IdentityError> {
    B64.decode(b64_value.trim().as_bytes())
        .map_err(|e| parse_err(format!("base64 decode: {e}")))
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

fn url_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                let val = u8::from_str_radix(hex, 16).unwrap_or(0);
                out.push(val);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_roundtrip() {
        let xml = b"<AuthnRequest>hello</AuthnRequest>";
        let url = build_redirect_url("https://idp.example/sso", "SAMLRequest", xml, Some("rs1"))
            .expect("build");
        assert!(url.contains("SAMLRequest="));
        assert!(url.contains("RelayState=rs1"));

        // Extract param.
        let param = url
            .split("SAMLRequest=")
            .nth(1)
            .expect("SAMLRequest param present")
            .split('&')
            .next()
            .expect("first segment");
        let decoded = decode_redirect_request(param).expect("decode");
        assert_eq!(decoded, xml);
    }

    #[test]
    fn post_form_contains_payload() {
        let xml = b"<Response>x</Response>";
        let html = build_post_form_html("https://sp.example/acs", "SAMLResponse", xml, Some("rs"));
        assert!(html.contains("action=\"https://sp.example/acs\""));
        assert!(html.contains("name=\"SAMLResponse\""));
        assert!(html.contains("RelayState"));
    }
}
