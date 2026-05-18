//! Outgoing Raft peer transport: implements openraft's `RaftNetworkFactory` and
//! `RaftNetwork` traits over tonic gRPC with mutual TLS.
//!
//! Each peer gets its own lazy `tonic::Channel` (created on first use and
//! cached thereafter). On any transport failure the channel is invalidated so
//! the next call attempts a fresh connection.

use std::io;
use std::sync::{Arc, Mutex};

use openraft::{
    error::{
        InstallSnapshotError, NetworkError as OraftNetworkError, RPCError, RaftError,
    },
    network::{RPCOption, RaftNetwork, RaftNetworkFactory},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, warn};

use crate::cluster::error::TransportError;
use crate::cluster::rpc::{
    raft_service_client::RaftServiceClient,
    AppendEntriesRequest as GrpcAer,
    InstallSnapshotRequest as GrpcIsr,
    VoteRequest as GrpcVr,
};
use crate::cluster::types::{HearthNode, HearthRaftConfig};

// ── TLS credential bundle ────────────────────────────────────────────────────

/// PEM-encoded TLS credentials shared by all peer connections from this node.
pub(crate) struct TlsCredentials {
    pub(crate) cert_pem: Vec<u8>,
    pub(crate) key_pem: Vec<u8>,
    pub(crate) ca_pem: Vec<u8>,
}

// ── HearthNetworkFactory ─────────────────────────────────────────────────────

/// Creates per-peer gRPC connections on demand.
///
/// Implements [`openraft::network::RaftNetworkFactory`] — openraft calls
/// `new_client(target, node)` whenever it needs a connection to a peer.
pub struct HearthNetworkFactory {
    creds: Arc<TlsCredentials>,
}

impl HearthNetworkFactory {
    /// Creates a new factory from PEM-encoded certificate material.
    ///
    /// `cert_pem` and `key_pem` are this node's identity presented to peers.
    /// `ca_pem` is the CA used to verify peer certificates.
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>, ca_pem: Vec<u8>) -> Self {
        Self {
            creds: Arc::new(TlsCredentials { cert_pem, key_pem, ca_pem }),
        }
    }
}

impl RaftNetworkFactory<HearthRaftConfig> for HearthNetworkFactory {
    type Network = HearthPeerNetwork;

    async fn new_client(&mut self, target: u64, node: &HearthNode) -> HearthPeerNetwork {
        debug!(node_id = target, addr = %node.addr, "allocating peer network slot");
        HearthPeerNetwork {
            target,
            addr: node.addr.clone(),
            creds: Arc::clone(&self.creds),
            channel: Mutex::new(None),
        }
    }
}

// ── HearthPeerNetwork ────────────────────────────────────────────────────────

/// gRPC connection to a single Raft peer.
///
/// Implements [`openraft::network::RaftNetwork`] — openraft calls the RPC
/// methods on this struct when it needs to replicate entries or vote.
///
/// The underlying [`Channel`] is lazily established and cached. Any transport
/// error invalidates the cache so the next call attempts a reconnect.
pub struct HearthPeerNetwork {
    target: u64,
    addr: String,
    creds: Arc<TlsCredentials>,
    /// Cached tonic `Channel`.
    ///
    /// Lock is held only long enough to clone the channel value — NEVER across
    /// an `.await`. Drop the guard, then await the cloned channel.
    channel: Mutex<Option<Channel>>,
}

impl HearthPeerNetwork {
    /// Returns the cached channel, or establishes a fresh mTLS connection.
    async fn get_or_connect(&self) -> Result<Channel, TransportError> {
        let cached = self
            .channel
            .lock()
            .map_err(|e| TransportError::Internal(e.to_string()))?
            .clone();

        if let Some(ch) = cached {
            return Ok(ch);
        }

        // Lock fully dropped before this await.
        let ch = self.connect_mtls().await?;

        // Store for next call; concurrent connections are harmless.
        if let Ok(mut guard) = self.channel.lock() {
            *guard = Some(ch.clone());
        }
        Ok(ch)
    }

    /// Opens a new mTLS-secured tonic channel to this peer.
    async fn connect_mtls(&self) -> Result<Channel, TransportError> {
        let identity = Identity::from_pem(&self.creds.cert_pem, &self.creds.key_pem);
        let ca = Certificate::from_pem(&self.creds.ca_pem);
        let tls = ClientTlsConfig::new().ca_certificate(ca).identity(identity);

        let endpoint = format!("https://{}", self.addr);
        debug!(node_id = self.target, addr = %endpoint, "connecting to peer over mTLS");

        Channel::from_shared(endpoint.clone())
            .map_err(|e| TransportError::Connect(Box::new(e)))?
            .tls_config(tls)
            .map_err(|e| TransportError::Tls(e.to_string()))?
            .connect()
            .await
            .map_err(|e| {
                warn!(node_id = self.target, addr = %endpoint, error = %e, "peer connection failed");
                TransportError::Connect(Box::new(e))
            })
    }

    /// Drops the cached channel so the next call reconnects.
    fn invalidate_channel(&self) {
        if let Ok(mut guard) = self.channel.lock() {
            *guard = None;
            debug!(node_id = self.target, addr = %self.addr, "peer channel invalidated");
        }
    }
}

// ── RaftNetwork impl ─────────────────────────────────────────────────────────

impl RaftNetwork<HearthRaftConfig> for HearthPeerNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<HearthRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<u64>,
        RPCError<u64, HearthNode, RaftError<u64>>,
    > {
        let payload = json_enc(&rpc).map_err(|e| net_err(TransportError::Serialize(e)))?;
        let ch = self.get_or_connect().await.map_err(net_err)?;
        let mut client = RaftServiceClient::new(ch);

        let resp = client
            .append_entries(GrpcAer { payload })
            .await
            .map_err(|e| {
                self.invalidate_channel();
                net_err(TransportError::Rpc(e))
            })?;

        json_dec(&resp.into_inner().payload).map_err(|e| net_err(TransportError::Deserialize(e)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<HearthRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, HearthNode, RaftError<u64, InstallSnapshotError>>,
    > {
        let payload =
            json_enc(&rpc).map_err(|e| net_err_ise(TransportError::Serialize(e)))?;
        let ch = self.get_or_connect().await.map_err(net_err_ise)?;
        let mut client = RaftServiceClient::new(ch);

        let resp = client
            .install_snapshot(GrpcIsr { payload })
            .await
            .map_err(|e| {
                self.invalidate_channel();
                net_err_ise(TransportError::Rpc(e))
            })?;

        json_dec(&resp.into_inner().payload)
            .map_err(|e| net_err_ise(TransportError::Deserialize(e)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, HearthNode, RaftError<u64>>> {
        let payload = json_enc(&rpc).map_err(|e| net_err(TransportError::Serialize(e)))?;
        let ch = self.get_or_connect().await.map_err(net_err)?;
        let mut client = RaftServiceClient::new(ch);

        let resp = client
            .vote(GrpcVr { payload })
            .await
            .map_err(|e| {
                self.invalidate_channel();
                net_err(TransportError::Rpc(e))
            })?;

        json_dec(&resp.into_inner().payload).map_err(|e| net_err(TransportError::Deserialize(e)))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn json_enc<T: Serialize>(val: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(val)
}

fn json_dec<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Wraps a [`TransportError`] as `RPCError::Network` for non-snapshot RPCs.
fn net_err<E: std::error::Error>(
    e: TransportError,
) -> RPCError<u64, HearthNode, E> {
    let io = io::Error::new(io::ErrorKind::BrokenPipe, e.to_string());
    RPCError::Network(OraftNetworkError::new(&io))
}

/// Wraps a [`TransportError`] as `RPCError::Network` for `install_snapshot`.
fn net_err_ise(
    e: TransportError,
) -> RPCError<u64, HearthNode, RaftError<u64, InstallSnapshotError>> {
    let io = io::Error::new(io::ErrorKind::BrokenPipe, e.to_string());
    RPCError::Network(OraftNetworkError::new(&io))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::LogId;

    /// Verifies factory produces a peer network with the expected address.
    #[tokio::test]
    async fn factory_creates_peer_with_correct_addr() {
        let mut factory =
            HearthNetworkFactory::new(b"cert".to_vec(), b"key".to_vec(), b"ca".to_vec());
        let node = HearthNode { addr: "127.0.0.1:8421".to_string() };
        let peer = factory.new_client(2, &node).await;
        assert_eq!(peer.addr, "127.0.0.1:8421");
        assert_eq!(peer.target, 2);
    }

    /// Confirms that a connection failure surfaces as `RPCError::Network`
    /// (no panic) so openraft can handle retries gracefully.
    #[tokio::test]
    async fn append_entries_returns_network_error_on_connection_failure() {
        let mut factory =
            HearthNetworkFactory::new(b"bad".to_vec(), b"bad".to_vec(), b"bad".to_vec());
        let node = HearthNode { addr: "127.0.0.1:19999".to_string() };
        let mut peer = factory.new_client(99, &node).await;

        let dummy = AppendEntriesRequest::<HearthRaftConfig> {
            vote: openraft::Vote::new(0, 1),
            prev_log_id: None,
            entries: vec![],
            leader_commit: None,
        };
        let result = peer
            .append_entries(dummy, RPCOption::new(std::time::Duration::from_millis(100)))
            .await;

        assert!(result.is_err(), "expected error on unreachable peer, got Ok");
        let e = result.unwrap_err();
        assert!(
            matches!(e, RPCError::Network(_)),
            "expected RPCError::Network, got {e:?}"
        );
    }

    /// Same guarantee for Vote.
    #[tokio::test]
    async fn vote_returns_network_error_on_connection_failure() {
        let mut factory =
            HearthNetworkFactory::new(b"bad".to_vec(), b"bad".to_vec(), b"bad".to_vec());
        let node = HearthNode { addr: "127.0.0.1:19999".to_string() };
        let mut peer = factory.new_client(99, &node).await;

        let dummy = VoteRequest::<u64> {
            vote: openraft::Vote::new(0, 1),
            last_log_id: Some(LogId::new(openraft::CommittedLeaderId::new(0, 1), 0)),
        };
        let result = peer
            .vote(dummy, RPCOption::new(std::time::Duration::from_millis(100)))
            .await;

        assert!(result.is_err(), "expected error on unreachable peer, got Ok");
    }
}
