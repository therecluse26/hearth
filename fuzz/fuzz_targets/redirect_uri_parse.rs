//! Fuzz target for redirect URI validation.
//!
//! Exercises `validate_redirect_uri` and `validate_scope_tokens` on arbitrary
//! byte sequences — they must never panic, only return `Ok` or `Err`.
//!
//! Corpus should include:
//! - Fragment-injected redirect URIs (e.g. "https://app.example.com/cb#fragment")
//! - Non-ASCII and Unicode sequences
//! - Wildcard patterns ("https://*.example.com/cb")
//! - Over-long URIs (>2048 bytes)
//! - HTTP vs HTTPS scheme variants
//! - Dangerous schemes (javascript:, data:, vbscript:)
//! - Loopback-only http URIs (localhost, 127.0.0.1, [::1])
//! - Custom deep-link schemes (myapp://callback)

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hearth::identity::fuzz_validate_redirect_uri(data);
});
