//! Storage engine: WAL, memtable, SSTs, and tiered hot/cold storage.
//!
//! The leaf layer. Pure data persistence with no knowledge of identity,
//! auth, or authorization concepts.

pub mod error;
// Internal modules not yet consumed by the public storage API (Step 7).
#[allow(dead_code)]
pub mod memtable;
#[allow(dead_code)]
pub mod sst;
pub mod wal;
