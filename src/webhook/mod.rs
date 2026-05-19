//! Webhook subscriptions and event delivery.
//!
//! Operators register HTTPS endpoints that receive signed HTTP POST
//! requests whenever audit events occur. Each subscription can filter by
//! event type and uses HMAC-SHA256 to verify authenticity.
//!
//! # Architecture
//!
//! - [`WebhookEngine`] — storage trait for subscriptions and delivery logs.
//! - [`EmbeddedWebhookEngine`] — storage-backed implementation.
//! - [`dispatcher`] — async background task that reads from a broadcast
//!   channel and delivers events with exponential-backoff retries.
//!
//! # Wire-up
//!
//! 1. Call [`dispatcher::audit_event_channel`] to get `(sender, receiver)`.
//! 2. Wrap the `EmbeddedAuditEngine` in a [`NotifyingAuditEngine`] (passing
//!    the `sender`) so every successful append broadcasts to the dispatcher.
//! 3. Spawn `dispatcher::run_dispatcher` as a background task.

pub mod dispatcher;
mod engine;
mod error;
mod keys;
mod types;

pub use engine::EmbeddedWebhookEngine;
pub use error::WebhookError;
pub use types::{
    CreateWebhookRequest, DeliveryQuery, DeliveryStatus, UpdateWebhookRequest, WebhookDelivery,
    WebhookQuery, WebhookSubscription, MAX_DELIVERY_ATTEMPTS, MIN_SECRET_LEN,
};

use crate::core::RealmId;
use crate::core::WebhookId;

/// Trait defining the webhook engine interface.
///
/// Covers subscription CRUD and delivery log writes. The async delivery
/// path lives in [`dispatcher`] and calls back into this trait to log
/// outcomes.
pub trait WebhookEngine: Send + Sync {
    /// Creates a new webhook subscription.
    fn create(&self, req: &CreateWebhookRequest) -> Result<WebhookSubscription, WebhookError>;

    /// Fetches a subscription by ID.
    fn get(&self, realm_id: &RealmId, id: &WebhookId) -> Result<WebhookSubscription, WebhookError>;

    /// Updates an existing subscription.
    fn update(
        &self,
        realm_id: &RealmId,
        id: &WebhookId,
        req: &UpdateWebhookRequest,
    ) -> Result<WebhookSubscription, WebhookError>;

    /// Deletes a subscription. Returns `WebhookError::NotFound` if absent.
    fn delete(&self, realm_id: &RealmId, id: &WebhookId) -> Result<(), WebhookError>;

    /// Lists subscriptions matching the query.
    fn list(&self, query: &WebhookQuery) -> Result<Vec<WebhookSubscription>, WebhookError>;

    /// Appends a delivery log entry.
    fn record_delivery(&self, delivery: &WebhookDelivery) -> Result<(), WebhookError>;

    /// Lists recent delivery log entries.
    fn list_deliveries(&self, query: &DeliveryQuery) -> Result<Vec<WebhookDelivery>, WebhookError>;
}

/// Wraps an [`crate::audit::AuditEngine`] and broadcasts each successful
/// append to the webhook dispatcher channel.
///
/// This is a decorator/newtype wrapper so the core `AuditEngine` trait
/// stays clean and the notification path is opt-in.
pub struct NotifyingAuditEngine {
    inner: std::sync::Arc<dyn crate::audit::AuditEngine>,
    sender: dispatcher::AuditEventSender,
}

impl NotifyingAuditEngine {
    pub fn new(
        inner: std::sync::Arc<dyn crate::audit::AuditEngine>,
        sender: dispatcher::AuditEventSender,
    ) -> Self {
        Self { inner, sender }
    }
}

impl crate::audit::AuditEngine for NotifyingAuditEngine {
    fn append(
        &self,
        event: &crate::audit::CreateAuditEvent,
    ) -> Result<crate::audit::AuditEvent, crate::audit::AuditError> {
        let result = self.inner.append(event)?;
        // Best-effort broadcast: if the channel is full or has no
        // receivers, we log and continue rather than failing the mutation.
        if let Err(e) = self.sender.send(result.clone()) {
            tracing::debug!("webhook broadcast send failed (no receivers?): {e}");
        }
        Ok(result)
    }

    fn query(
        &self,
        query: &crate::audit::AuditQuery,
    ) -> Result<Vec<crate::audit::AuditEvent>, crate::audit::AuditError> {
        self.inner.query(query)
    }

    fn verify_integrity(
        &self,
        realm_id: &RealmId,
        start: Option<crate::core::Timestamp>,
        end: Option<crate::core::Timestamp>,
    ) -> Result<bool, crate::audit::AuditError> {
        self.inner.verify_integrity(realm_id, start, end)
    }

    fn get_retention_config(
        &self,
        realm_id: &RealmId,
    ) -> Result<crate::audit::AuditRetentionConfig, crate::audit::AuditError> {
        self.inner.get_retention_config(realm_id)
    }

    fn set_retention_config(
        &self,
        realm_id: &RealmId,
        config: &crate::audit::AuditRetentionConfig,
    ) -> Result<(), crate::audit::AuditError> {
        self.inner.set_retention_config(realm_id, config)
    }

    fn prune_before(
        &self,
        realm_id: &RealmId,
        cutoff: crate::core::Timestamp,
    ) -> Result<u64, crate::audit::AuditError> {
        self.inner.prune_before(realm_id, cutoff)
    }
}
