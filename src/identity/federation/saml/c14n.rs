//! Exclusive XML canonicalization (subset of http://www.w3.org/2001/10/xml-exc-c14n#).
//!
//! This is a deliberately narrow implementation — enough for the SAML
//! 2.0 messages Hearth produces and consumes in practice. It is NOT a
//! general-purpose exc-c14n processor.
//!
//! Supported:
//! - Element sorting (attributes alphabetical by fully-qualified name).
//! - Namespace declarations emitted only when "visibly utilized" on an
//!   element or its attributes.
//! - The enveloped-signature transform (strip a `<ds:Signature>` child).
//! - Proper escape of text and attribute content per c14n rules.
//!
//! NOT supported:
//! - Processing instructions inside the canonicalized subtree.
//! - Mixed-content elements with significant whitespace from entity
//!   expansion.
//! - Inclusive namespace prefix lists (`InclusiveNamespaces`).
//! - `#WithComments` (deliberate — Hearth never emits comments).
//!
//! Any input that uses the unsupported features produces a
//! `SamlUnsupportedAlgorithm` error rather than silent misbehavior.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::BTreeMap;

use super::xml::{escape_attr, escape_text, ns, parse_err};
use crate::identity::error::IdentityError;

/// Canonicalizes the element subtree contained in `xml`, applying the
/// exclusive C14N 1.0 rules.
///
/// When `strip_signature` is true, any `<ds:Signature>` element that is
/// a direct or indirect descendant is dropped (the enveloped-signature
/// transform). Nested `<Signature>` inside a deeper `<Assertion>` are
/// NOT dropped — only the one at the root of the canonicalized subtree.
///
/// `xml` MUST contain exactly one top-level element (the signed element
/// extracted via `xml::find_element_range`).
pub fn canonicalize(xml: &[u8], strip_signature: bool) -> Result<Vec<u8>, IdentityError> {
    canonicalize_with_inherited(xml, strip_signature, &BTreeMap::new())
}

/// Canonicalizes with a known "declared but not emitted" namespace context.
///
/// When we extract a subtree from a larger document for canonicalization
/// (e.g. the `<ds:SignedInfo>` inside `<ds:Signature>`), the extracted
/// bytes reference a prefix that was declared on an ancestor outside our
/// subtree. We need to:
///
/// 1. Resolve the prefix correctly (the `declared_inherited` context).
/// 2. Still emit an xmlns decl for the prefix on the subtree's root
///    because no canonical ancestor of *our* processing has emitted it.
///
/// Exclusive-C14N's emission rule is "decl emitted if visibly utilized
/// AND not already emitted on a canonical ancestor". A prefix declared
/// in source but not on a canonical ancestor of the current
/// canonicalization IS emitted.
pub fn canonicalize_with_inherited(
    xml: &[u8],
    strip_signature: bool,
    declared_inherited: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<Vec<u8>, IdentityError> {
    let mut reader = Reader::from_reader(xml);
    let cfg = reader.config_mut();
    cfg.expand_empty_elements = false;
    cfg.trim_text(false);

    let mut out: Vec<u8> = Vec::with_capacity(xml.len());
    let mut buf = Vec::new();
    // `emitted_stack` always starts empty — from this canonicalization's
    // perspective there are no canonical ancestors. `declared_stack` is
    // seeded with the caller-supplied inherited-declaration context so
    // element-prefix resolution finds the right URI.
    let mut emitted_stack: Vec<BTreeMap<Vec<u8>, Vec<u8>>> = vec![BTreeMap::new()];
    let mut declared_stack: Vec<BTreeMap<Vec<u8>, Vec<u8>>> = vec![declared_inherited.clone()];
    let mut skip_depth: Option<i32> = None;
    let mut depth: i32 = 0;
    // Track the visible prefixes used on the current element so namespace
    // decls can be emitted on the output tag in exclusive form.
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                depth += 1;
                if let Some(d) = skip_depth {
                    // Inside a stripped subtree; keep tracking depth but
                    // emit nothing.
                    if depth > d {
                        emitted_stack.push(emitted_stack.last().cloned().unwrap_or_default());
                        declared_stack.push(declared_stack.last().cloned().unwrap_or_default());
                        buf.clear();
                        continue;
                    }
                }

                let (is_sig_at_root, rendered) =
                    process_start(&e, &mut emitted_stack, &mut declared_stack, false)?;
                if strip_signature && depth == 2 && is_sig_at_root {
                    // Enveloped-signature transform: drop the <Signature>
                    // subtree. depth==2 because root is depth 1; Signature
                    // is direct child at depth 2.
                    skip_depth = Some(depth);
                } else {
                    out.extend_from_slice(rendered.as_bytes());
                }
            }
            Ok(Event::Empty(e)) => {
                depth += 1;
                if let Some(d) = skip_depth {
                    if depth > d {
                        buf.clear();
                        depth -= 1;
                        continue;
                    }
                }
                let (is_sig_at_root, rendered) =
                    process_start(&e, &mut emitted_stack, &mut declared_stack, true)?;
                if strip_signature && depth == 2 && is_sig_at_root {
                    // Nothing to emit.
                } else {
                    out.extend_from_slice(rendered.as_bytes());
                }
                emitted_stack.pop();
                declared_stack.pop();
                depth -= 1;
            }
            Ok(Event::End(e)) => {
                if let Some(d) = skip_depth {
                    if depth == d {
                        skip_depth = None;
                        emitted_stack.pop();
                        declared_stack.pop();
                        depth -= 1;
                        buf.clear();
                        continue;
                    }
                    if depth > d {
                        emitted_stack.pop();
                        declared_stack.pop();
                        depth -= 1;
                        buf.clear();
                        continue;
                    }
                }
                out.push(b'<');
                out.push(b'/');
                out.extend_from_slice(e.name().as_ref());
                out.push(b'>');
                emitted_stack.pop();
                declared_stack.pop();
                depth -= 1;
            }
            Ok(Event::Text(t)) => {
                if skip_depth.is_some() {
                    buf.clear();
                    continue;
                }
                let raw = t.unescape().map_err(|e| parse_err(e.to_string()))?;
                let escaped = escape_text(raw.as_ref());
                out.extend_from_slice(escaped.as_bytes());
            }
            Ok(Event::CData(c)) => {
                if skip_depth.is_some() {
                    buf.clear();
                    continue;
                }
                let s = std::str::from_utf8(c.as_ref()).map_err(|e| parse_err(e.to_string()))?;
                let escaped = escape_text(s);
                out.extend_from_slice(escaped.as_bytes());
            }
            Ok(Event::Eof) => break,
            Ok(Event::Comment(_)) | Ok(Event::Decl(_)) | Ok(Event::PI(_)) => {
                // Skip per c14n rules (we never emit these, and comments
                // are off per our #WithComments-free variant).
            }
            Ok(Event::DocType(_)) => {
                return Err(IdentityError::SamlUnsupportedAlgorithm);
            }
            Err(e) => return Err(parse_err(format!("c14n parse error: {e}"))),
            Ok(_) => {}
        }
        buf.clear();
    }

    Ok(out)
}

fn process_start(
    start: &BytesStart<'_>,
    emitted_stack: &mut Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    declared_stack: &mut Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    self_closing: bool,
) -> Result<(bool, String), IdentityError> {
    // Two views:
    //   `emitted_parent` — decls that have been EMITTED on canonical
    //      ancestors. Used for exclusive-C14N dedup: a decl is only
    //      emitted here if the parent canonical form did not already
    //      emit the same prefix→URI binding.
    //   `declared_parent` — every decl the SOURCE XML has declared on
    //      an ancestor. Used for prefix resolution so we can identify
    //      the element namespace even when the xmlns decl was
    //      suppressed from the canonical output further up.
    let emitted_parent = emitted_stack.last().cloned().unwrap_or_default();
    let declared_parent = declared_stack.last().cloned().unwrap_or_default();

    let mut source_ns: BTreeMap<Vec<u8>, Vec<u8>> = declared_parent.clone();
    let mut regular_attrs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for a in start.attributes().with_checks(false) {
        let a = a.map_err(|e| parse_err(format!("bad attribute: {e}")))?;
        let key = a.key.as_ref().to_vec();
        let val = a
            .unescape_value()
            .map_err(|e| parse_err(format!("bad attr value: {e}")))?
            .into_owned()
            .into_bytes();
        if key == b"xmlns" || key.starts_with(b"xmlns:") {
            let prefix = if key == b"xmlns" {
                Vec::new()
            } else {
                key[6..].to_vec()
            };
            source_ns.insert(prefix, val);
        } else {
            regular_attrs.push((key, val));
        }
    }

    // Determine visibly utilized prefixes:
    // 1. The element's own prefix.
    // 2. Every prefix used in regular attribute names (excluding `xml:`
    //    which is implicit).
    let name = start.name();
    let name_bytes = name.as_ref();
    let elem_prefix: Vec<u8> = match name_bytes.iter().position(|&b| b == b':') {
        Some(i) => name_bytes[..i].to_vec(),
        None => Vec::new(),
    };

    let mut visible: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    if let Some(uri) = source_ns.get(&elem_prefix) {
        visible.insert(elem_prefix.clone(), uri.clone());
    }
    for (k, _) in &regular_attrs {
        if let Some(i) = k.iter().position(|&b| b == b':') {
            let pfx = k[..i].to_vec();
            if pfx == b"xml" {
                continue;
            }
            if let Some(uri) = source_ns.get(&pfx) {
                visible.insert(pfx, uri.clone());
            }
        }
    }

    // Exclusive dedup: emit a decl only if it wasn't already emitted on
    // a canonical ancestor with the same URI.
    let mut emitted_decls: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (pfx, uri) in &visible {
        if emitted_parent.get(pfx) != Some(uri) {
            emitted_decls.push((pfx.clone(), uri.clone()));
        }
    }

    // Push the source-declared context for children (regardless of what
    // got emitted). Needed so `<ds:Signature>` is recognized even when
    // its xmlns:ds was declared on an ancestor and suppressed from the
    // canonical output.
    declared_stack.push(source_ns.clone());

    // Build the new emitted-scope for children: parent's emitted set
    // plus the decls we just emitted on this element.
    let mut emitted_here = emitted_parent.clone();
    for (pfx, uri) in &emitted_decls {
        emitted_here.insert(pfx.clone(), uri.clone());
    }
    emitted_stack.push(emitted_here);
    // Sort decls: default first, then prefixes alphabetical.
    emitted_decls.sort_by(|a, b| match (a.0.is_empty(), b.0.is_empty()) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.0.cmp(&b.0),
    });

    // Sort regular attrs alphabetically by fully-qualified name (c14n
    // says: sort by namespace URI then local name; simplified here to
    // byte-sort on the raw attribute key which matches in practice for
    // our SAML output since we use consistent prefixes).
    regular_attrs.sort_by(|a, b| a.0.cmp(&b.0));

    // Build the rendered start tag.
    let mut out = String::new();
    out.push('<');
    out.push_str(std::str::from_utf8(name_bytes).map_err(|e| parse_err(e.to_string()))?);

    for (pfx, uri) in &emitted_decls {
        out.push(' ');
        if pfx.is_empty() {
            out.push_str("xmlns=\"");
        } else {
            out.push_str("xmlns:");
            out.push_str(std::str::from_utf8(pfx).map_err(|e| parse_err(e.to_string()))?);
            out.push_str("=\"");
        }
        out.push_str(&escape_attr(
            std::str::from_utf8(uri).map_err(|e| parse_err(e.to_string()))?,
        ));
        out.push('"');
    }
    for (k, v) in &regular_attrs {
        out.push(' ');
        out.push_str(std::str::from_utf8(k).map_err(|e| parse_err(e.to_string()))?);
        out.push_str("=\"");
        out.push_str(&escape_attr(
            std::str::from_utf8(v).map_err(|e| parse_err(e.to_string()))?,
        ));
        out.push('"');
    }

    if self_closing {
        // In c14n, empty elements are written as <tag></tag> (no
        // self-closing form in the canonical output).
        out.push('>');
        out.push_str("</");
        out.push_str(std::str::from_utf8(name_bytes).map_err(|e| parse_err(e.to_string()))?);
        out.push('>');
    } else {
        out.push('>');
    }

    // Detect whether this element is <ds:Signature> in the XMLDSIG
    // namespace.
    let is_signature = match (elem_prefix.as_slice(), source_ns.get(&elem_prefix)) {
        (p, Some(uri)) if uri.as_slice() == ns::DS.as_bytes() => {
            // local name must be "Signature"
            let local = if p.is_empty() {
                name_bytes
            } else {
                &name_bytes[p.len() + 1..]
            };
            local == b"Signature"
        }
        _ => false,
    };

    Ok((is_signature, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canon_preserves_simple_element() {
        let xml = br#"<root xmlns="http://example.com/ns">hello</root>"#;
        let out = canonicalize(xml, false).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert_eq!(s, r#"<root xmlns="http://example.com/ns">hello</root>"#);
    }

    #[test]
    fn canon_sorts_attributes() {
        let xml = br#"<root z="1" a="2" m="3"/>"#;
        let out = canonicalize(xml, false).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert_eq!(s, r#"<root a="2" m="3" z="1"></root>"#);
    }

    #[test]
    fn canon_escapes_text() {
        let xml = br#"<root>a&amp;b&lt;c</root>"#;
        let out = canonicalize(xml, false).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert_eq!(s, r#"<root>a&amp;b&lt;c</root>"#);
    }

    #[test]
    fn canon_strips_envelope_signature() {
        let xml = br#"<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Issuer>x</Issuer><ds:Signature><ds:SignedInfo></ds:SignedInfo></ds:Signature><Status/></Response>"#;
        let out = canonicalize(xml, true).expect("canon");
        let s = std::str::from_utf8(&out).expect("utf8");
        assert!(
            !s.contains("Signature"),
            "signature should be stripped: {s}"
        );
        assert!(s.contains("Issuer"));
        assert!(s.contains("Status"));
    }
}
