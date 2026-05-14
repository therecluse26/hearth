//! Error types for the webhook engine.

use crate::core::WebhookId;

/// Errors that can occur in the webhook engine.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// A storage I/O error occurred.
    #[error("storage error: {reason}")]
    Storage { reason: String },

    /// Serialization or deserialization failed.
    #[error("serialization error: {reason}")]
    Serialization { reason: String },

    /// The requested webhook subscription was not found.
    #[error("webhook not found: {id}")]
    NotFound { id: WebhookId },

    /// The provided URL is not valid.
    #[error("invalid URL: {reason}")]
    InvalidUrl { reason: String },

    /// The signing secret is too short.
    #[error("secret too short: minimum 16 bytes")]
    SecretTooShort,
}

impl From<crate::storage::StorageError> for WebhookError {
    fn from(e: crate::storage::StorageError) -> Self {
        Self::Storage {
            reason: e.to_string(),
        }
    }
}
