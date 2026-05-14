//! Webhook subscription and delivery log types.

use crate::audit::AuditAction;
use crate::core::{AuditEventId, RealmId, Timestamp, WebhookDeliveryId, WebhookId};
use serde::{Deserialize, Serialize};

/// Minimum length (bytes) required for a webhook signing secret.
pub const MIN_SECRET_LEN: usize = 16;

/// Maximum number of delivery attempts before a delivery is marked failed.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;

/// Backoff delays (seconds) indexed by attempt number (0-based).
///
/// Attempt 0: immediate, 1: 5 s, 2: 25 s, 3: 125 s, 4: 625 s (≈10 min).
pub const BACKOFF_SECONDS: [u64; 5] = [0, 5, 25, 125, 625];

/// A registered webhook subscription that receives audit events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookSubscription {
    /// Unique identifier for this subscription.
    pub id: WebhookId,
    /// The realm this subscription is scoped to.
    pub realm_id: RealmId,
    /// The target URL that receives POST requests.
    pub url: String,
    /// HMAC-SHA256 signing secret (stored in plaintext; access is admin-only).
    pub secret: String,
    /// Whether this subscription is currently active.
    pub enabled: bool,
    /// Event types to deliver. Empty means all audit actions are delivered.
    pub event_filters: Vec<AuditAction>,
    /// When the subscription was created.
    pub created_at: Timestamp,
    /// When the subscription was last modified.
    pub updated_at: Timestamp,
}

impl WebhookSubscription {
    /// Returns true if this subscription matches the given audit action.
    pub fn matches(&self, action: &AuditAction) -> bool {
        self.enabled && (self.event_filters.is_empty() || self.event_filters.contains(action))
    }
}

/// Request to create a new webhook subscription.
#[derive(Clone, Debug)]
pub struct CreateWebhookRequest {
    pub realm_id: RealmId,
    pub url: String,
    /// Raw signing secret (minimum 16 bytes).
    pub secret: String,
    pub enabled: bool,
    /// Empty slice = subscribe to all events.
    pub event_filters: Vec<AuditAction>,
}

/// Request to update an existing webhook subscription.
///
/// `None` fields are left unchanged.
#[derive(Clone, Debug, Default)]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub secret: Option<String>,
    pub enabled: Option<bool>,
    pub event_filters: Option<Vec<AuditAction>>,
}

/// Outcome of a single delivery attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// The target server returned a 2xx response.
    Success,
    /// The attempt failed (network error or non-2xx response).
    Failed,
}

/// A single webhook delivery attempt record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Unique identifier for this delivery record.
    pub id: WebhookDeliveryId,
    /// The subscription that triggered this delivery.
    pub webhook_id: WebhookId,
    /// Realm context (denormalized for efficient querying).
    pub realm_id: RealmId,
    /// The audit event that was delivered.
    pub event_id: AuditEventId,
    /// Which attempt number this is (1-based).
    pub attempt: u32,
    /// Outcome of this attempt.
    pub status: DeliveryStatus,
    /// HTTP response status code, if a response was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    /// Error message if the attempt failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// When this attempt was made.
    pub attempted_at: Timestamp,
}

/// Query parameters for listing webhook subscriptions.
#[derive(Clone, Debug)]
pub struct WebhookQuery {
    pub realm_id: RealmId,
    pub enabled_only: bool,
}

/// Query parameters for listing delivery logs.
#[derive(Clone, Debug)]
pub struct DeliveryQuery {
    pub realm_id: RealmId,
    pub webhook_id: Option<WebhookId>,
    pub limit: Option<usize>,
}
