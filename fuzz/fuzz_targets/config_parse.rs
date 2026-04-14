//! Fuzz target for configuration parsing.
//!
//! Feeds arbitrary bytes to `Config::from_yaml_str()` and verifies it
//! never panics — it must always return `Ok` or `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Convert arbitrary bytes to a string (lossy is fine — we're testing robustness)
    let input = String::from_utf8_lossy(data);

    // Must never panic, regardless of input
    let _ = hearth::config::Config::from_yaml_str(&input);
});
