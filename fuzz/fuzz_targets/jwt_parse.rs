//! Fuzz target for JWT parsing.
//!
//! Feeds arbitrary strings to `decode_claims_unverified` and
//! `verify_token_signature` — they must never panic, only return
//! `Ok` or `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);

    // decode_claims_unverified: must never panic on arbitrary tokens
    let _ = hearth::identity::decode_claims_unverified(&input);

    // verify_token_signature with a dummy key: must never panic
    let dummy_key = [0u8; 32];
    let _ = hearth::identity::verify_token_signature(&input, &dummy_key);
});
