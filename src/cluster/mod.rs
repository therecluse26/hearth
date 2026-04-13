//! Cluster layer: Raft consensus via `openraft`.
//!
//! Handles log replication, leader election, membership changes, and snapshots.
//! Invisible in single-node mode.
