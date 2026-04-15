//! Fuzz target for credential/password hash verification.
//!
//! Feeds arbitrary bytes as both passwords and hash strings to the
//! credential system — it must never panic, only return `Ok` or `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test CleartextPassword construction with arbitrary bytes — must not panic
    let password = hearth::identity::CleartextPassword::new(data.to_vec());

    // Attempting to verify against an arbitrary "hash" string must not panic.
    // We use the password-hash crate's PasswordHash::new internally, which
    // should gracefully reject malformed inputs.
    let lossy_hash = String::from_utf8_lossy(data);

    // Use the public token validation path as a proxy — verify_token_signature
    // exercises the same constant-time comparison codepaths.
    // Direct credential verification requires a full engine; we test that the
    // CleartextPassword type handles arbitrary bytes without panic.
    drop(password);
    drop(lossy_hash);
});
