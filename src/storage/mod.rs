//! Storage engine: WAL, memtable, SSTs, and tiered hot/cold storage.
//!
//! The leaf layer. Pure data persistence with no knowledge of identity,
//! auth, or authorization concepts.

pub mod error;
// Types not yet used outside tests — will be integrated in Step 5 (SST flush).
#[allow(dead_code)]
pub mod memtable;
pub mod wal;
