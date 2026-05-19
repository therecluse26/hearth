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
//!  │  ClusterEngine (public-facing wrapper)               │
//!  │    • single-node bypass (zero Raft overhead)         │
//!  │    • leader write routing via client_write           │
//!  │    • follower read staleness via reads_allowed flag  │
//!  └──────────────────────────────────────────────────────┘
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

pub mod engine;
pub(crate) mod error;
pub mod log_store;
pub mod network;
pub(crate) mod rpc;
pub mod server;
pub mod state_machine;
pub mod types;

pub use engine::{ClusterBuildError, ClusterEngine, ClusterError};
pub use log_store::{HearthLogReader, HearthLogStore};
pub use network::HearthNetworkFactory;
pub use server::{serve, IncomingRpcDispatch, NoopDispatch, RaftRpcHandler};
pub use state_machine::HearthStateMachine;
pub use types::{HearthLogData, HearthLogResponse, HearthNode, HearthRaftConfig, RaftCommand};
