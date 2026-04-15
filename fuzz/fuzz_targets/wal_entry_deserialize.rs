//! Fuzz target for WAL entry deserialization.
//!
//! Feeds arbitrary bytes to `WalEntry::deserialize` — it must never
//! panic, only return `Ok` or `Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input
    let _ = hearth::storage::wal::WalEntry::deserialize(data);
});
