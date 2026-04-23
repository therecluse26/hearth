//! Fuzz target for the federation ID-token claim parser.
//!
//! Feeds arbitrary bytes to
//! [`hearth::identity::federation::fuzz_parse_id_token_claims`] — it
//! must never panic, only return `Ok` or `Err`.
//!
//! Why: an ID token payload is attacker-controlled JSON (signed by the
//! upstream IdP, but an attacker who compromises the IdP or tricks
//! Hearth into talking to a hostile one controls the bytes). Every
//! field is bounded by `serde(default)` and `Option<_>`, but the
//! parser itself must reject malformed input without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed raw bytes: the parser must handle non-UTF-8 and all the
    // JSON edge cases (deep nesting, giant numbers, surrogates, …)
    // without panicking. Return value is ignored — we only care about
    // the absence of an abort.
    let _ = hearth::identity::federation::fuzz_parse_id_token_claims(data);
});
