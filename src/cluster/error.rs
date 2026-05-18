//! Error types for the cluster gRPC transport layer.

use std::fmt;

/// Error produced by the Hearth peer transport.
#[derive(Debug)]
pub enum TransportError {
    /// gRPC channel could not be established (e.g. connection refused, DNS failure).
    Connect(Box<dyn std::error::Error + Send + Sync>),
    /// An established gRPC call returned a non-OK status.
    Rpc(tonic::Status),
    /// Serializing an outgoing payload to JSON failed.
    Serialize(serde_json::Error),
    /// Deserializing an incoming payload from JSON failed.
    Deserialize(serde_json::Error),
    /// TLS configuration or certificate error.
    Tls(String),
    /// Internal error (e.g. poisoned mutex).
    Internal(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "peer connect: {e}"),
            Self::Rpc(s) => write!(f, "peer RPC: code={}, message={}", s.code(), s.message()),
            Self::Serialize(e) => write!(f, "payload serialize: {e}"),
            Self::Deserialize(e) => write!(f, "payload deserialize: {e}"),
            Self::Tls(e) => write!(f, "TLS: {e}"),
            Self::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}
