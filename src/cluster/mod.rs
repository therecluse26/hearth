//! Cluster layer: Raft consensus via `openraft`.
//!
//! Handles log replication, leader election, membership changes, and snapshots.
//! Invisible in single-node mode — the module is compiled unconditionally but
//! the engine is only started when `config.cluster` is `Some`.
//!
//! ## Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────┐
//!  │  HearthNetworkFactory (outgoing RPCs)                │
//!  │    └─ HearthPeerNetwork per peer                     │
//!  │         • lazy mTLS gRPC channel                     │
//!  │         • serde_json encode/decode openraft payloads │
//!  └──────────────────────────────────────────────────────┘
//!  ┌──────────────────────────────────────────────────────┐
//!  │  RaftRpcHandler / serve() (incoming RPCs)            │
//!  │    • tonic Server with ServerTlsConfig (mTLS)        │
//!  │    • delegates to IncomingRpcDispatch                │
//!  └──────────────────────────────────────────────────────┘
//! ```

pub(crate) mod error;
pub mod log_store;
pub(crate) mod rpc;
pub mod network;
pub mod server;
pub mod types;

pub use log_store::{HearthLogReader, HearthLogStore};
pub use network::HearthNetworkFactory;
pub use server::{serve, IncomingRpcDispatch, NoopDispatch, RaftRpcHandler};
pub use types::{HearthLogData, HearthLogResponse, HearthNode, HearthRaftConfig};
