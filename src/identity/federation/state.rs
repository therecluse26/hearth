//! Helpers for the short-lived state that federation logins carry
//! between the `begin` redirect and the `callback` completion.
//!
//! Three independent primitives:
//!
//! 1. [`generate_state_token`] / [`generate_nonce`] — cryptographically
//!    random 256-bit values, base64url-encoded, no padding. Used for
//!    the OAuth `state` parameter and the OIDC `nonce`.
//! 2. [`generate_pkce_verifier`] / [`pkce_s256_challenge`] — the S256
//!    PKCE pair. Hearth acts as the *client* here (relying party) —
//!    it generates the verifier, sends the challenge on `authorize`,
//!    and returns the verifier on `token`. (The provider-side PKCE
//!    code lives in `src/identity/engine.rs`.)
//! 3. [`compute_confirm_ticket_mac`] — HMAC-SHA256 binding a confirm-
//!    to-link ticket cookie to the matched `UserId`. Mirrors the
//!    pattern used by `src/protocol/web/oauth_consent.rs` for the
//!    authorization-pending ticket.
//!
//! None of these primitives touch storage; they produce opaque values
//! that callers persist via engine methods (`put_federation_state`
//! etc.) and read back via the corresponding `take_*` methods.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use ring::rand::SecureRandom;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::core::UserId;
use crate::identity::IdentityError;

/// Raw byte length of opaque tokens (state, nonce, verifier seed).
///
/// 32 bytes = 256 bits of entropy. Well above the 128-bit OAuth floor
/// and matches the existing magic-link / invitation token sizes.
const TOKEN_BYTES: usize = 32;

/// Generates a random opaque state token.
///
/// Base64url-encoded with no padding, exactly 43 ASCII characters.
/// Unique per login attempt; persisted under `fed:state:{token}` with
/// a single-use consume on callback.
pub fn generate_state_token() -> Result<String, IdentityError> {
    fill_random_b64(TOKEN_BYTES)
}

/// Generates a random OIDC nonce.
///
/// Echoed in the upstream ID token; any mismatch on callback rejects
/// the login. Same entropy as [`generate_state_token`].
pub fn generate_nonce() -> Result<String, IdentityError> {
    fill_random_b64(TOKEN_BYTES)
}

/// Generates a PKCE code verifier.
///
/// Per RFC 7636 §4.1 the verifier MUST be between 43 and 128 unreserved
/// URL characters. A 32-byte random value base64url-encoded produces
/// exactly 43 characters and satisfies the unreserved-character
/// constraint.
pub fn generate_pkce_verifier() -> Result<String, IdentityError> {
    fill_random_b64(TOKEN_BYTES)
}

/// Computes the PKCE S256 code challenge for a given verifier.
///
/// Per RFC 7636 §4.2:
/// `code_challenge = BASE64URL-NO-PAD(SHA256(ASCII(verifier)))`
///
/// S256 is mandatory; plain-text `code_challenge_method=plain` is not
/// supported by any connector Hearth ships.
pub fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Computes the HMAC-SHA256 tag binding a confirm-link ticket cookie
/// to its owning `UserId`.
///
/// The cookie is `{ticket}.{b64url(tag)}`; validation re-computes the
/// tag from the trusted `(secret, user_id, ticket)` triple and
/// constant-time compares via [`verify_confirm_ticket_mac`]. A
/// cross-user replay fails MAC verification even if the attacker
/// knows the ticket string.
///
/// Mirrors `oauth_consent::compute_ticket_mac` so the same cookie
/// secret can be reused server-wide without mixing key material.
pub fn compute_confirm_ticket_mac(secret: &[u8; 32], user_id: &UserId, ticket: &str) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC-SHA256 accepts any 32-byte key");
    mac.update(b"fed-confirm|");
    mac.update(user_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(ticket.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Constant-time-verifies a confirm-link ticket tag.
pub fn verify_confirm_ticket_mac(
    secret: &[u8; 32],
    user_id: &UserId,
    ticket: &str,
    candidate_tag: &str,
) -> bool {
    let expected = compute_confirm_ticket_mac(secret, user_id, ticket);
    expected.as_bytes().ct_eq(candidate_tag.as_bytes()).into()
}

/// Internal: fills `n` random bytes and base64url-encodes them.
fn fill_random_b64(n: usize) -> Result<String, IdentityError> {
    let mut bytes = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| IdentityError::SigningError {
            reason: "failed to generate random token".to_string(),
        })?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_token_is_base64url_with_expected_length() {
        let token = generate_state_token().expect("generate");
        assert_eq!(
            token.len(),
            43,
            "32 random bytes → 43 base64url chars: {token}"
        );
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "unreserved url-safe chars only: {token}"
        );
    }

    #[test]
    fn state_tokens_are_unique() {
        let a = generate_state_token().expect("generate");
        let b = generate_state_token().expect("generate");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_and_state_are_independent_and_distinct() {
        let s = generate_state_token().expect("state");
        let n = generate_nonce().expect("nonce");
        assert_ne!(s, n);
        assert_eq!(s.len(), n.len());
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_spec_vector() {
        // RFC 7636 Appendix B.
        //
        //   verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        //   challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_s256_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_verifier_meets_rfc_length_floor() {
        let v = generate_pkce_verifier().expect("generate");
        assert!(
            v.len() >= 43 && v.len() <= 128,
            "RFC 7636 §4.1 bounds: got {}",
            v.len()
        );
    }

    #[test]
    fn pkce_challenge_is_deterministic_for_same_verifier() {
        let v = "the-same-verifier";
        assert_eq!(pkce_s256_challenge(v), pkce_s256_challenge(v));
    }

    #[test]
    fn pkce_challenge_differs_across_verifiers() {
        assert_ne!(pkce_s256_challenge("a"), pkce_s256_challenge("b"));
    }

    #[test]
    fn confirm_ticket_mac_roundtrip() {
        let secret = [7u8; 32];
        let user = UserId::generate();
        let ticket = "ticket-abc";
        let tag = compute_confirm_ticket_mac(&secret, &user, ticket);
        assert!(verify_confirm_ticket_mac(&secret, &user, ticket, &tag));
    }

    #[test]
    fn confirm_ticket_mac_rejects_wrong_user() {
        let secret = [7u8; 32];
        let alice = UserId::generate();
        let bob = UserId::generate();
        let ticket = "ticket-abc";
        let tag = compute_confirm_ticket_mac(&secret, &alice, ticket);
        assert!(!verify_confirm_ticket_mac(&secret, &bob, ticket, &tag));
    }

    #[test]
    fn confirm_ticket_mac_rejects_wrong_ticket() {
        let secret = [7u8; 32];
        let user = UserId::generate();
        let tag = compute_confirm_ticket_mac(&secret, &user, "ticket-a");
        assert!(!verify_confirm_ticket_mac(&secret, &user, "ticket-b", &tag));
    }

    #[test]
    fn confirm_ticket_mac_rejects_wrong_secret() {
        let user = UserId::generate();
        let ticket = "abc";
        let tag = compute_confirm_ticket_mac(&[7u8; 32], &user, ticket);
        assert!(!verify_confirm_ticket_mac(&[8u8; 32], &user, ticket, &tag));
    }

    #[test]
    fn confirm_ticket_mac_domain_separated_from_other_cookies() {
        // The MAC input is prefixed with a literal `"fed-confirm|"` so
        // a tag minted for the OAuth consent cookie can't be reused
        // here. Regression guard: if the domain separator is removed or
        // renamed, this assertion should be revisited.
        let secret = [7u8; 32];
        let user = UserId::generate();
        let ticket = "abc";
        let tag = compute_confirm_ticket_mac(&secret, &user, ticket);

        // Hand-compute a tag using the *consent* cookie's prefix shape
        // (no prefix, matching `oauth_consent::compute_ticket_mac`).
        let mut naive = <Hmac<Sha256> as Mac>::new_from_slice(&secret)
            .expect("HMAC-SHA256 accepts any 32-byte key");
        naive.update(user.as_uuid().as_bytes());
        naive.update(b"|");
        naive.update(ticket.as_bytes());
        let naive_tag = URL_SAFE_NO_PAD.encode(naive.finalize().into_bytes());
        assert_ne!(tag, naive_tag);
    }
}
