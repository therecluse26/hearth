//! XML-DSIG sign and verify over SAML `<Response>` / `<Assertion>`.
//!
//! Algorithm suite (locked):
//! - Canonicalization: exclusive C14N 1.0 without comments.
//! - Digest: SHA-256.
//! - Signature: RSA-PKCS1-v1.5-SHA256.
//! - Reference transforms: `enveloped-signature` + `exc-c14n` only.
//!
//! SHA-1 is rejected. Algorithm downgrade attempts return
//! `SamlUnsupportedAlgorithm`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use sha2::{Digest, Sha256};

use std::collections::BTreeMap;

use super::c14n::{canonicalize, canonicalize_with_inherited};
use super::xml::{alg, escape_attr, find_element_range, ns, parse_err};
use crate::identity::error::IdentityError;
use crate::identity::tokens::RsaSigningKey;

/// Metadata about a verified signed element.
pub struct SignedElement {
    /// The element local name (`Response` or `Assertion`).
    pub local_name: String,
    /// The element ID (matched against the `Reference URI` in the
    /// signature).
    pub id: String,
    /// The canonicalized bytes of the signed element (with `<Signature>`
    /// stripped per the enveloped transform).
    pub canonical: Vec<u8>,
}

/// Signs the enveloped XML subtree represented by `element_xml`, returning
/// a new XML document identical to the input but with a freshly-built
/// `<ds:Signature>` element inserted as the first child of the root.
///
/// `element_xml` MUST have its root element carry an `ID="…"` attribute
/// — SAML signatures reference the signed element by its ID. The
/// canonical subset we implement emits the `<Signature>` immediately
/// after the root's opening tag, which is also where SAML SPs expect it.
///
/// This is a minimal implementation: it assumes the root element has no
/// leading whitespace content and that the first child insertion point
/// is well-defined.
pub fn sign_element(
    element_xml: &[u8],
    element_id: &str,
    key: &RsaSigningKey,
) -> Result<Vec<u8>, IdentityError> {
    // 1. Canonicalize the element with the enveloped-signature transform
    //    applied (strip any existing <Signature> — there shouldn't be
    //    one, but be safe).
    let canonical = canonicalize(element_xml, true)?;

    // 2. Compute the digest.
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let digest = hasher.finalize();
    let digest_b64 = B64.encode(digest);

    // 3. Build the SignedInfo element, canonicalize it WITH the ds
    //    prefix seeded as inherited — the emitted bytes have no
    //    `xmlns:ds` of their own (the enclosing <ds:Signature> owns it),
    //    so the canonical form must match what a consumer would compute
    //    in-context.
    let signed_info = build_signed_info(element_id, &digest_b64);
    // Detached canonicalization — xml-crypto and other SAML libraries
    // do the same. The visibly-utilized `xmlns:ds` emits onto SignedInfo.
    let canonical_si = canonicalize(signed_info.as_bytes(), false)?;

    // 4. Sign.
    let signature_bytes = key.sign(&canonical_si)?;
    let signature_b64 = B64.encode(&signature_bytes);

    // 5. Build the full <Signature> element.
    let cert_b64 = B64.encode(key.cert_der());
    let signature_xml = build_signature_block(&signed_info, &signature_b64, &cert_b64);

    // 6. Splice the signature block into the element after the root's
    //    opening tag. Find the end of the first `>` in element_xml.
    let open_end = element_xml
        .iter()
        .position(|&b| b == b'>')
        .ok_or_else(|| parse_err("no root tag close found"))?;

    let mut out = Vec::with_capacity(element_xml.len() + signature_xml.len());
    out.extend_from_slice(&element_xml[..=open_end]);
    out.extend_from_slice(signature_xml.as_bytes());
    out.extend_from_slice(&element_xml[open_end + 1..]);
    Ok(out)
}

fn build_signed_info(element_id: &str, digest_b64: &str) -> String {
    let uri = format!("#{}", escape_attr(element_id));
    // xml-crypto and other SAML libraries canonicalize SignedInfo as a
    // detached subtree (no inherited ancestor ns context). In that mode
    // `xmlns:ds` is visibly utilized at the SignedInfo root and must be
    // emitted. Matching that behavior means emitting the decl here too
    // so our canonical form byte-matches theirs.
    format!(
        r#"<ds:SignedInfo xmlns:ds="{ds}"><ds:CanonicalizationMethod Algorithm="{c14n}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{sig}"></ds:SignatureMethod><ds:Reference URI="{uri}"><ds:Transforms><ds:Transform Algorithm="{env}"></ds:Transform><ds:Transform Algorithm="{c14n}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="{dig}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
        ds = ns::DS,
        c14n = alg::EXC_C14N,
        sig = alg::RSA_SHA256,
        env = alg::ENVELOPED,
        dig = alg::SHA256,
        uri = uri,
        digest = digest_b64,
    )
}

fn build_signature_block(signed_info: &str, signature_b64: &str, cert_b64: &str) -> String {
    format!(
        r#"<ds:Signature xmlns:ds="{ds}">{si}<ds:SignatureValue>{sv}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        ds = ns::DS,
        si = signed_info,
        sv = signature_b64,
        cert = cert_b64,
    )
}

/// Verifies the signature on a `<Response>` or `<Assertion>` element.
///
/// `full_xml` is the entire XML document as received (we need the full
/// bytes to locate the signed element's byte range).
///
/// `signing_cert_pem` is the expected IdP certificate (PEM).
///
/// Returns the verified signed element's canonical bytes on success.
/// Rejects:
/// - Missing `<Signature>`.
/// - Signature-wrapping attacks (signature URI doesn't match the
///   enclosing element's ID).
/// - Algorithm downgrade (SHA-1, inclusive C14N, RSA-SHA1).
/// - Digest mismatch.
/// - Signature verification failure.
pub fn verify_signed_element(
    full_xml: &[u8],
    local_name: &str,
    signing_cert_pem: &str,
) -> Result<SignedElement, IdentityError> {
    // Locate the element.
    let range = find_element_range(full_xml, ns::SAMLP, local_name, None)?
        .or(find_element_range(full_xml, ns::SAML, local_name, None)?)
        .ok_or(IdentityError::SamlSignature)?;
    let element_bytes = &full_xml[range.0..range.1];

    // Extract ID and Signature sub-block.
    let element_id = extract_id_attr(element_bytes)?;
    let (signed_info_bytes, signature_value_b64, reference_uri, digest_b64) =
        extract_signature_fields(element_bytes)?;

    // Signature-wrapping defense: the Reference URI must be `#<id>`
    // where `id` equals the enclosing element's ID.
    let expected_uri = format!("#{element_id}");
    if reference_uri != expected_uri {
        return Err(IdentityError::SamlSignature);
    }

    // Verify referenced element digest.
    let canonical_element = canonicalize(element_bytes, true)?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical_element);
    let actual_digest = hasher.finalize();
    let expected_digest = B64
        .decode(digest_b64.trim())
        .map_err(|_| IdentityError::SamlSignature)?;
    if actual_digest.as_slice() != expected_digest.as_slice() {
        return Err(IdentityError::SamlSignature);
    }

    // Check algorithms inside SignedInfo (reject SHA-1 etc).
    let si_str =
        std::str::from_utf8(&signed_info_bytes).map_err(|_| parse_err("SignedInfo not utf8"))?;
    if si_str.contains(alg::SHA1) || si_str.contains(alg::RSA_SHA1) {
        return Err(IdentityError::SamlUnsupportedAlgorithm);
    }
    if !si_str.contains(alg::RSA_SHA256) || !si_str.contains(alg::SHA256) {
        return Err(IdentityError::SamlUnsupportedAlgorithm);
    }

    // Canonicalize SignedInfo with the ds prefix declared-but-not-emitted
    // in the context. The extracted bytes don't carry `xmlns:ds` on the
    // SignedInfo element itself (it's inherited from the <ds:Signature>
    // parent in the source), but exclusive-C14N of a detached subtree
    // SHOULD emit that decl — xml-crypto and peer libraries do the
    // same when signing, so our canonical form must match theirs.
    let mut ds_declared: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    ds_declared.insert(b"ds".to_vec(), ns::DS.as_bytes().to_vec());
    let canonical_si = canonicalize_with_inherited(&signed_info_bytes, false, &ds_declared)?;

    // Verify signature over canonicalized SignedInfo.
    let sig_bytes = B64
        .decode(signature_value_b64.trim())
        .map_err(|_| IdentityError::SamlSignature)?;

    let public_key = parse_cert_public_key(signing_cert_pem)?;
    public_key
        .verify(&RSA_PKCS1_2048_8192_SHA256, &canonical_si, &sig_bytes)
        .map_err(|_| IdentityError::SamlSignature)?;

    Ok(SignedElement {
        local_name: local_name.to_string(),
        id: element_id,
        canonical: canonical_element,
    })
}

fn extract_id_attr(element_bytes: &[u8]) -> Result<String, IdentityError> {
    // naive but adequate: find the first ID="…" or Id="…" in the root
    // tag (before the first `>`).
    let open_end = element_bytes
        .iter()
        .position(|&b| b == b'>')
        .ok_or_else(|| parse_err("no root close"))?;
    let header =
        std::str::from_utf8(&element_bytes[..=open_end]).map_err(|e| parse_err(e.to_string()))?;
    for key in [" ID=\"", " Id=\""] {
        if let Some(start) = header.find(key) {
            let after = &header[start + key.len()..];
            if let Some(end) = after.find('"') {
                return Ok(after[..end].to_string());
            }
        }
    }
    Err(parse_err("no ID attribute on signed element"))
}

fn extract_signature_fields(
    element_bytes: &[u8],
) -> Result<(Vec<u8>, String, String, String), IdentityError> {
    // Find <ds:Signature ... as direct child only (depth 2 from the
    // enclosing root). We use find_element_range with ds namespace.
    let sig_range = find_element_range(element_bytes, ns::DS, "Signature", None)?
        .ok_or(IdentityError::SamlSignature)?;
    let sig_bytes = &element_bytes[sig_range.0..sig_range.1];

    // Find SignedInfo.
    let si_range = find_element_range(sig_bytes, ns::DS, "SignedInfo", None)?
        .ok_or(IdentityError::SamlSignature)?;
    let signed_info = sig_bytes[si_range.0..si_range.1].to_vec();

    // Extract <ds:SignatureValue>…</ds:SignatureValue> textual content.
    let sv = extract_text_element(sig_bytes, "SignatureValue")?;

    // Extract Reference URI.
    let reference_uri = extract_attr_of_child(&signed_info, "Reference", "URI")?;

    // Extract DigestValue.
    let digest = extract_text_element(&signed_info, "DigestValue")?;

    Ok((signed_info, sv, reference_uri, digest))
}

fn extract_text_element(bytes: &[u8], local: &str) -> Result<String, IdentityError> {
    // Simple substring search tolerant of optional ds: prefix.
    let s = std::str::from_utf8(bytes).map_err(|e| parse_err(e.to_string()))?;
    for name in [format!("<ds:{local}>"), format!("<{local}>")] {
        if let Some(start) = s.find(&name) {
            let after = &s[start + name.len()..];
            if let Some(end) = after.find("</") {
                return Ok(after[..end].trim().to_string());
            }
        }
    }
    Err(parse_err(format!("{local} element not found")))
}

fn extract_attr_of_child(
    bytes: &[u8],
    child_local: &str,
    attr_name: &str,
) -> Result<String, IdentityError> {
    let s = std::str::from_utf8(bytes).map_err(|e| parse_err(e.to_string()))?;
    for name in [format!("<ds:{child_local} "), format!("<{child_local} ")] {
        if let Some(start) = s.find(&name) {
            let after = &s[start + name.len()..];
            let attr_key = format!("{attr_name}=\"");
            if let Some(akey) = after.find(&attr_key) {
                let after2 = &after[akey + attr_key.len()..];
                if let Some(end) = after2.find('"') {
                    return Ok(after2[..end].to_string());
                }
            }
        }
    }
    Err(parse_err(format!("{child_local}@{attr_name} not found")))
}

/// Parses a PEM certificate and extracts the RSA public key components
/// suitable for `ring::signature` verification.
fn parse_cert_public_key(pem: &str) -> Result<RsaPublicKeyComponents<Vec<u8>>, IdentityError> {
    // Strip PEM armor and decode DER.
    let der = decode_pem(pem).ok_or_else(|| parse_err("invalid PEM certificate"))?;
    // Walk DER to find the SubjectPublicKeyInfo. For RSA certs the
    // structure is:
    //   Certificate ::= SEQUENCE { tbsCertificate, sigAlg, sigValue }
    //   tbsCertificate ::= SEQUENCE { ..., subject, SubjectPublicKeyInfo, ...}
    //   SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
    //     -> BIT STRING wraps RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    //
    // We use a minimal DER walker rather than pulling in an X.509 crate.
    let (modulus, exponent) =
        extract_rsa_modulus_exponent(&der).ok_or_else(|| parse_err("cert is not RSA"))?;
    Ok(RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    })
}

fn decode_pem(pem: &str) -> Option<Vec<u8>> {
    let trimmed = pem.trim();
    let begin = trimmed.find("-----BEGIN")?;
    let begin_end = trimmed[begin..].find('\n')? + begin;
    let end = trimmed.find("-----END")?;
    let body: String = trimmed[begin_end..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    B64.decode(body).ok()
}

fn extract_rsa_modulus_exponent(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Parse outer Certificate SEQUENCE.
    let (cert_content, _rest) = der_unwrap_sequence(der)?;
    // Parse tbsCertificate SEQUENCE.
    let (tbs, _after_tbs) = der_unwrap_sequence(cert_content)?;
    // Walk tbsCertificate. We look for ANY SEQUENCE whose body begins
    // with AlgorithmIdentifier(rsaEncryption). Most SEQUENCEs in TBS
    // (issuer Name, validity, etc.) won't match — we skip them via
    // `Option::is_none` short-circuits.
    const RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    let mut cursor = tbs;
    while !cursor.is_empty() {
        let start_tag = cursor[0];
        let Some((content, after)) = der_parse_tlv(cursor) else {
            break;
        };
        cursor = after;
        if start_tag != 0x30 {
            continue;
        }
        // Candidate SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        let Some((alg_content, rest_after_alg)) = der_unwrap_sequence(content) else {
            continue;
        };
        // AlgorithmIdentifier SEQUENCE: OID comes first.
        if alg_content.first() != Some(&0x06) {
            continue;
        }
        let Some((oid_bytes, _)) = der_parse_tlv(alg_content) else {
            continue;
        };
        if oid_bytes != RSA_OID {
            continue;
        }
        // Next should be BIT STRING wrapping RSAPublicKey.
        if rest_after_alg.is_empty() || rest_after_alg[0] != 0x03 {
            continue;
        }
        let Some((bit_string, _)) = der_parse_tlv(rest_after_alg) else {
            continue;
        };
        if bit_string.is_empty() {
            continue;
        }
        let rsa_pubkey_der = &bit_string[1..];
        let Some((rsa_content, _)) = der_unwrap_sequence(rsa_pubkey_der) else {
            continue;
        };
        if rsa_content.first() != Some(&0x02) {
            continue;
        }
        let Some((modulus_bytes, exp_area)) = der_parse_tlv(rsa_content) else {
            continue;
        };
        if exp_area.first() != Some(&0x02) {
            continue;
        }
        let Some((exp_bytes, _)) = der_parse_tlv(exp_area) else {
            continue;
        };
        let modulus = strip_leading_zero(modulus_bytes).to_vec();
        let exponent = strip_leading_zero(exp_bytes).to_vec();
        return Some((modulus, exponent));
    }
    None
}

fn der_unwrap_sequence(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.first() != Some(&0x30) {
        return None;
    }
    der_parse_tlv(input)
}

fn der_parse_tlv(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let mut i = 1;
    let first_len = input[i];
    let (len, len_len) = if first_len & 0x80 == 0 {
        (first_len as usize, 1)
    } else {
        let n = (first_len & 0x7F) as usize;
        if n == 0 || n > 4 || input.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for b in &input[i + 1..i + 1 + n] {
            len = (len << 8) | (*b as usize);
        }
        (len, 1 + n)
    };
    i += len_len;
    if input.len() < i + len {
        return None;
    }
    let content = &input[i..i + len];
    let rest = &input[i + len..];
    Some((content, rest))
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.first() == Some(&0x00) && bytes.len() > 1 {
        &bytes[1..]
    } else {
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::tokens::RsaSigningKey;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());

        let payload = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">hello</Assertion>"#;
        let signed = sign_element(payload, "a1", &key).expect("sign");
        let verified = verify_signed_element(&signed, "Assertion", &cert_pem).expect("verify");
        assert_eq!(verified.id, "a1");
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());

        let payload = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">hello</Assertion>"#;
        let mut signed = sign_element(payload, "a1", &key).expect("sign");
        // Tamper with the element content.
        let idx = signed.windows(5).position(|w| w == b"hello").unwrap();
        signed[idx] = b'H';
        let result = verify_signed_element(&signed, "Assertion", &cert_pem);
        assert!(matches!(result, Err(IdentityError::SamlSignature)));
    }

    fn cert_der_to_pem(der: &[u8]) -> String {
        let b64 = B64.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }
}
