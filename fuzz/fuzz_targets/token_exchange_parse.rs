//! Fuzz target for token exchange body parsing.
//!
//! Exercises the full parse + validation pipeline for OAuth 2.0 token
//! exchange request bodies — JSON deserialization, grant_type dispatch,
//! scope normalization, redirect URI validation, and PKCE code_verifier
//! length checks. Must never panic on arbitrary input.
//!
//! Corpus should include:
//! - Spec-valid authorization_code requests
//! - Spec-valid refresh_token and client_credentials requests
//! - Mismatched grant_type (e.g. "authorization_code" body with no code)
//! - Malformed UTF-8 encoded as scope values
//! - Over-long code_verifier (>128 bytes)
//! - redirect_uri injection attempts (fragment, javascript:, data: schemes)

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hearth::identity::fuzz_parse_token_exchange(data);
});
