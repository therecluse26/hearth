//! Raft type configuration and application-layer command types.

use serde::{Deserialize, Serialize};

use crate::core::RealmId;

/// Information stored alongside each node in the Raft membership config.
///
/// Automatically satisfies `openraft::Node` via the blanket impl, which
/// requires `Debug + Clone + Default + PartialEq + Eq + Serialize + Deserialize`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HearthNode {
    /// gRPC peer address for this node, e.g. `"10.0.0.1:8421"`.
    pub addr: String,
}

/// Commands replicated through Raft and applied to the storage engine.
///
/// Every variant carries `leader_timestamp` — the wall-clock microseconds
/// stamped by the leader at the time the command was proposed.  Followers
/// MUST NOT substitute a local clock reading; they use this field verbatim
/// so time-ordered reads are consistent across the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftCommand {
    /// Insert or update a single key-value pair.
    Put {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    /// Delete a single key.
    Delete {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        key: Vec<u8>,
    },
    /// Atomically write multiple key-value pairs for a single realm.
    Batch {
        /// Leader wall-clock timestamp (microseconds since UNIX epoch).
        leader_timestamp: i64,
        realm: RealmId,
        /// `(key, value)` pairs to write atomically.
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    },
}

/// Openraft `D` type alias — keeps the `declare_raft_types!` binding stable.
pub type HearthLogData = RaftCommand;

/// Response returned by the state machine after each applied log entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HearthLogResponse {
    /// Optional result bytes returned to the caller.
    pub payload: Vec<u8>,
}

openraft::declare_raft_types!(
    /// Type configuration for Hearth's Raft consensus engine.
    pub HearthRaftConfig:
        D             = HearthLogData,
        R             = HearthLogResponse,
        NodeId        = u64,
        Node          = HearthNode,
        Entry         = openraft::Entry<HearthRaftConfig>,
        SnapshotData  = std::io::Cursor<Vec<u8>>,
        AsyncRuntime  = openraft::TokioRuntime,
);
