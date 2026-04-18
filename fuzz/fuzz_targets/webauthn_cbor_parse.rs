//! Fuzz target for `WebAuthn` CBOR/authenticator-data parsing.
//!
//! Feeds arbitrary bytes to the `WebAuthn` parsing pipeline — attestation
//! objects, authenticator data, `clientDataJSON`, and COSE key extraction.
//! These parsers must never panic on untrusted input, only return `Ok` or `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hearth::identity::fuzz_parse_webauthn(data);
});
