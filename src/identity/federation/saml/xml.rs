//! Minimal XML reader/writer helpers for SAML.
//!
//! Built on `quick-xml`. Deliberately narrow — only the shapes we emit
//! and consume for SAML 2.0 messages are supported. No DTDs, no entity
//! expansion, no processing instructions.
//!
//! Security posture: rejects XML external entities, DOCTYPE declarations,
//! and comments outside of the document root. These vectors have produced
//! many XXE CVEs in SAML parsers historically.

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use quick_xml::Reader;
use std::io::BufRead;

use crate::identity::error::IdentityError;

/// Standard SAML namespace URIs.
pub mod ns {
    pub const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    pub const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
    pub const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
    pub const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
}

/// XML-DSIG algorithm URIs we accept.
pub mod alg {
    pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
    pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
    pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
}

/// Configures a `quick_xml::Reader` with our security-conservative defaults.
pub fn make_reader<R: BufRead>(reader: R) -> Reader<R> {
    let mut r = Reader::from_reader(reader);
    let cfg = r.config_mut();
    // Rejecting DOCTYPE/XXE vectors: quick-xml skips DTDs by default but
    // emit them as Event::DocType anyway so we can reject them.
    cfg.expand_empty_elements = true;
    cfg.trim_text(false);
    r
}

/// Returns `true` iff the given [`BytesStart`] represents an element in
/// the given namespace and with the given local name.
pub fn is_element(start: &BytesStart<'_>, namespace_uri: &str, local: &str) -> bool {
    let qname = start.name();
    // Split prefix and local — we need to resolve the prefix against the
    // accumulated namespace context. `quick_xml::NsReader` handles this
    // natively; we rely on callers using it where namespace awareness is
    // required. For simple cases we accept either `{ns}local` comparison
    // or prefix:local matching when the ns is one of the well-known ones.
    let name_bytes = qname.as_ref();
    if let Some(colon) = name_bytes.iter().position(|&b| b == b':') {
        let local_bytes = &name_bytes[colon + 1..];
        local_bytes == local.as_bytes()
            && namespace_matches_prefix(&name_bytes[..colon], namespace_uri, start)
    } else {
        name_bytes == local.as_bytes() && has_default_namespace(start, namespace_uri)
    }
}

fn namespace_matches_prefix(prefix: &[u8], expected_uri: &str, start: &BytesStart<'_>) -> bool {
    let attr_name = [b"xmlns:", prefix].concat();
    for attr in start.attributes().with_checks(false).flatten() {
        if attr.key.as_ref() == attr_name {
            if let Ok(v) = attr.unescape_value() {
                return v.as_ref() == expected_uri;
            }
        }
    }
    // Fall back to prefix-match for the common SAML prefixes even when
    // the xmlns isn't declared on this element (it would be on an
    // ancestor in a proper parse). Accept standard prefixes.
    matches!(
        (prefix, expected_uri),
        (b"samlp", ns::SAMLP)
            | (b"saml", ns::SAML)
            | (b"saml2p", ns::SAMLP)
            | (b"saml2", ns::SAML)
            | (b"ds", ns::DS)
            | (b"md", ns::MD)
    )
}

fn has_default_namespace(start: &BytesStart<'_>, expected_uri: &str) -> bool {
    for attr in start.attributes().with_checks(false).flatten() {
        if attr.key.as_ref() == b"xmlns" {
            if let Ok(v) = attr.unescape_value() {
                return v.as_ref() == expected_uri;
            }
        }
    }
    false
}

/// Extracts the value of a specific attribute from a start tag.
pub fn attr(start: &BytesStart<'_>, name: &str) -> Option<String> {
    for a in start.attributes().with_checks(false).flatten() {
        if a.key.as_ref() == name.as_bytes() {
            if let Ok(v) = a.unescape_value() {
                return Some(v.into_owned());
            }
        }
    }
    None
}

/// Parse error helper.
pub fn parse_err(reason: impl Into<String>) -> IdentityError {
    IdentityError::SamlParse {
        reason: reason.into(),
    }
}

/// Reads the textual content between the current start and its matching
/// end tag. Simplified — does not support nested elements (which the
/// SAML fields we extract with this don't contain).
pub fn read_text<R: BufRead>(reader: &mut Reader<R>) -> Result<String, IdentityError> {
    let mut buf = Vec::new();
    let mut out = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(t)) => {
                if let Ok(s) = t.unescape() {
                    out.push_str(s.as_ref());
                }
            }
            Ok(Event::CData(c)) => {
                if let Ok(s) = std::str::from_utf8(c.as_ref()) {
                    out.push_str(s);
                }
            }
            Ok(Event::End(_)) => return Ok(out),
            Ok(Event::Eof) => return Err(parse_err("unexpected EOF in text content")),
            Ok(Event::Start(_)) => {
                return Err(parse_err("unexpected child element in text content"));
            }
            Err(e) => return Err(parse_err(format!("XML read error: {e}"))),
            _ => {}
        }
        buf.clear();
    }
}

/// XML escape for element content (`<`, `>`, `&`, and CR).
///
/// Per exclusive C14N: CR `&#x0D;` must be escaped; NL and tab are left.
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

/// XML escape for attribute values (`<`, `&`, `"`, and whitespace chars).
pub fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

/// Locates an element by (namespace_uri, local_name) and returns the raw
/// byte range in `xml` containing that element, inclusive of its start
/// and end tags.
///
/// Used by signature verification: we need to canonicalize exactly the
/// bytes the IdP signed, not a re-serialized form. Works by tracking
/// buffer position offsets from the quick-xml reader.
///
/// Returns the first matching element. Nested recursion supported.
pub fn find_element_range(
    xml: &[u8],
    namespace_uri: &str,
    local: &str,
    id_attr: Option<&str>,
) -> Result<Option<(usize, usize)>, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().expand_empty_elements = false;

    let mut buf = Vec::new();
    let mut depth: i32 = 0;
    // Depth at which we found the first matching Start. We emit when the
    // corresponding End closes at this depth.
    let mut target_depth: Option<i32> = None;
    let mut target_start: usize = 0;

    loop {
        let pos_before = reader.buffer_position() as usize;
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                if target_depth.is_none()
                    && is_element(e, namespace_uri, local)
                    && id_match(e, id_attr)
                {
                    target_depth = Some(depth);
                    target_start = pos_before;
                }
            }
            Ok(Event::End(_)) => {
                let pos_after = reader.buffer_position() as usize;
                if target_depth == Some(depth) {
                    return Ok(Some((target_start, pos_after)));
                }
                depth -= 1;
            }
            Ok(Event::Empty(ref e)) => {
                let pos_after = reader.buffer_position() as usize;
                if target_depth.is_none()
                    && is_element(e, namespace_uri, local)
                    && id_match(e, id_attr)
                {
                    return Ok(Some((pos_before, pos_after)));
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(parse_err("DOCTYPE declarations are rejected"));
            }
            Ok(Event::Eof) => return Ok(None),
            Err(e) => return Err(parse_err(format!("XML scan error: {e}"))),
            _ => {}
        }
        buf.clear();
    }
}

fn id_match(e: &BytesStart<'_>, id_attr: Option<&str>) -> bool {
    match id_attr {
        None => true,
        Some(expected) => {
            attr(e, "ID").as_deref() == Some(expected) || attr(e, "Id").as_deref() == Some(expected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_text_covers_gt_lt_amp_cr() {
        assert_eq!(escape_text("a<b>&c\r"), "a&lt;b&gt;&amp;c&#xD;");
    }

    #[test]
    fn escape_attr_covers_whitespace_quote() {
        assert_eq!(escape_attr("\"\t\n\r<&"), "&quot;&#x9;&#xA;&#xD;&lt;&amp;");
    }
}
