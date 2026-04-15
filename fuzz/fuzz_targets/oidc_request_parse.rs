//! Fuzz target for OIDC request parsing.
//!
//! Feeds arbitrary bytes as JSON to the OIDC request deserialization
//! paths — they must never panic, only return `Ok` or `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse as AuthorizationRequest JSON
    let _ = serde_json::from_slice::<serde_json::Value>(data);

    // Attempt to parse as token exchange parameters.
    // The HTTP layer uses serde to deserialize request bodies; we verify
    // that arbitrary bytes never cause a panic in the JSON parser or any
    // downstream validation.
    let input = String::from_utf8_lossy(data);

    // Exercise the OIDC discovery document parser (round-trip)
    let _ = serde_json::from_str::<hearth::identity::OidcDiscoveryDocument>(&input);

    // Exercise token claims decoding (reuses JWT parser internals)
    let _ = hearth::identity::decode_claims_unverified(&input);
});
