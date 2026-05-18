//! Raft peer gRPC server: listens for incoming RPCs from cluster peers,
//! authenticates them via mutual TLS, and forwards to the local Raft node.
//!
//! The server is independent of the generic openraft `Raft<C, ...>` type by
//! accepting an `Arc<dyn IncomingRpcDispatch>` — callers wire this up once the
//! full Raft engine is initialised (see HEA-600).

use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::cluster::rpc::{
    raft_service_server::{RaftService, RaftServiceServer},
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use crate::config::ClusterConfig;

// ── IncomingRpcDispatch ───────────────────────────────────────────────────────

/// Dispatch interface for incoming peer RPCs.
///
/// Implemented by the Raft engine integration once a `openraft::Raft` handle
/// is available. Until then, the server returns `UNAVAILABLE`.
pub trait IncomingRpcDispatch: Send + Sync + 'static {
    /// Handle an `AppendEntries` RPC from the cluster leader.
    fn append_entries(
        &self,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;

    /// Handle a `Vote` RPC from a cluster candidate.
    fn vote(
        &self,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;

    /// Handle one snapshot chunk from the leader.
    /// Payload is JSON-encoded `InstallSnapshotRequest<HearthRaftConfig>`.
    fn install_snapshot(
        &self,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

// ── RaftRpcHandler ────────────────────────────────────────────────────────────

/// tonic service handler that forwards requests to an [`IncomingRpcDispatch`].
#[derive(Clone)]
pub struct RaftRpcHandler<D> {
    dispatch: Arc<D>,
}

impl<D: IncomingRpcDispatch> RaftRpcHandler<D> {
    /// Creates a handler wrapping the given dispatcher.
    pub fn new(dispatch: Arc<D>) -> Self {
        Self { dispatch }
    }
}

#[tonic::async_trait]
impl<D: IncomingRpcDispatch> RaftService for RaftRpcHandler<D> {
    async fn append_entries(
        &self,
        request: Request<AppendEntriesRequest>,
    ) -> Result<Response<AppendEntriesResponse>, Status> {
        let payload = request.into_inner().payload;
        debug!("received AppendEntries from peer");

        self.dispatch
            .append_entries(&payload)
            .await
            .map(|resp| Response::new(AppendEntriesResponse { payload: resp.into() }))
            .map_err(|e| {
                warn!(error = %e, "AppendEntries dispatch error");
                Status::internal(e)
            })
    }

    async fn vote(
        &self,
        request: Request<VoteRequest>,
    ) -> Result<Response<VoteResponse>, Status> {
        let payload = request.into_inner().payload;
        debug!("received Vote from peer");

        self.dispatch
            .vote(&payload)
            .await
            .map(|resp| Response::new(VoteResponse { payload: resp.into() }))
            .map_err(|e| {
                warn!(error = %e, "Vote dispatch error");
                Status::internal(e)
            })
    }

    async fn install_snapshot(
        &self,
        request: Request<InstallSnapshotRequest>,
    ) -> Result<Response<InstallSnapshotResponse>, Status> {
        let payload = request.into_inner().payload;
        debug!("received InstallSnapshot chunk from peer");

        self.dispatch
            .install_snapshot(&payload)
            .await
            .map(|resp| Response::new(InstallSnapshotResponse { payload: resp.into() }))
            .map_err(|e| {
                warn!(error = %e, "InstallSnapshot dispatch error");
                Status::internal(e)
            })
    }
}

// ── serve ─────────────────────────────────────────────────────────────────────

/// Starts the Raft peer gRPC server bound to `config.peer_address`.
///
/// Requires `tls_cert_path`, `tls_key_path`, and `tls_ca_cert_path` to be
/// readable PEM files. Enforces mutual TLS — unauthenticated peers are
/// rejected at the TLS handshake.
///
/// Returns when the server shuts down (caller should run this in a task).
pub async fn serve<D: IncomingRpcDispatch>(
    config: &ClusterConfig,
    dispatch: Arc<D>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert = tokio::fs::read(&config.tls_cert_path).await?;
    let key = tokio::fs::read(&config.tls_key_path).await?;
    let ca = tokio::fs::read(&config.tls_ca_cert_path).await?;

    let identity = Identity::from_pem(cert, key);
    let ca_cert = Certificate::from_pem(ca);

    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert);

    let addr: SocketAddr = config.peer_address.parse().map_err(|e| {
        format!("invalid peer_address '{}': {e}", config.peer_address)
    })?;

    info!(
        node_id = config.node_id,
        addr = %addr,
        "Raft peer gRPC server starting (mTLS)"
    );

    Server::builder()
        .tls_config(tls)?
        .add_service(RaftServiceServer::new(RaftRpcHandler::new(dispatch)))
        .serve(addr)
        .await?;

    Ok(())
}

// ── NoopDispatch (test helper) ────────────────────────────────────────────────

/// A no-op dispatcher that returns UNAVAILABLE for all RPCs.
///
/// Useful in tests and before the Raft engine is initialised.
#[derive(Clone)]
pub struct NoopDispatch;

impl IncomingRpcDispatch for NoopDispatch {
    async fn append_entries(&self, _payload: &[u8]) -> Result<Vec<u8>, String> {
        Err("Raft engine not initialised".to_string())
    }

    async fn vote(&self, _payload: &[u8]) -> Result<Vec<u8>, String> {
        Err("Raft engine not initialised".to_string())
    }

    async fn install_snapshot(&self, _payload: &[u8]) -> Result<Vec<u8>, String> {
        Err("Raft engine not initialised".to_string())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies the handler can be created and cloned (tonic requires Clone).
    #[test]
    fn handler_is_clone() {
        let handler = RaftRpcHandler::new(Arc::new(NoopDispatch));
        let _clone = handler.clone();
    }

    /// Verifies NoopDispatch returns an error rather than panicking.
    #[tokio::test]
    async fn noop_dispatch_returns_error() {
        let d = NoopDispatch;
        let result = d.append_entries(b"{}").await;
        assert!(result.is_err());
    }
}
