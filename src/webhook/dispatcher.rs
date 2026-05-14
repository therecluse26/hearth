//! Background webhook dispatcher.
//!
//! Receives audit events through a broadcast channel, finds matching
//! webhook subscriptions, signs the payload with HMAC-SHA256, and
//! delivers it via HTTP POST with exponential-backoff retries.
//!
//! The dispatcher runs as a long-lived `tokio::task`. It is intentionally
//! decoupled from the request path: a delivery failure never bubbles up to
//! the user who triggered the audit event.
//!
//! # Signature scheme
//!
//! The request body is the JSON-serialized `AuditEvent`. Hearth adds:
//!
//! ```text
//! X-Hearth-Signature-256: sha256=<hex(HMAC-SHA256(secret, body))>
//! X-Hearth-Event: <audit_action_string>
//! X-Hearth-Delivery: <webhook_delivery_id>
//! ```
//!
//! This follows GitHub's webhook signature convention so operators can reuse
//! their existing verification middleware.

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::broadcast;
use tracing::{debug, error, warn};

use crate::audit::AuditEvent;
use crate::core::{Clock, WebhookDeliveryId};

use super::engine::make_delivery;
use super::types::{DeliveryStatus, WebhookQuery, BACKOFF_SECONDS, MAX_DELIVERY_ATTEMPTS};
use super::WebhookEngine;

type HmacSha256 = Hmac<Sha256>;

/// A broadcast sender that pushes `AuditEvent` values to the dispatcher.
pub type AuditEventSender = broadcast::Sender<AuditEvent>;
/// A broadcast receiver that receives `AuditEvent` values from appends.
pub type AuditEventReceiver = broadcast::Receiver<AuditEvent>;

/// Creates a broadcast channel pair for audit event notifications.
///
/// Capacity of 1024 means up to 1024 events can be buffered before slow
/// receivers start seeing lag-drops (`RecvError::Lagged`). The dispatcher
/// handles lagged errors gracefully (logs + skips).
pub fn audit_event_channel() -> (AuditEventSender, AuditEventReceiver) {
    broadcast::channel(1_024)
}

/// Runs the webhook dispatcher loop.
///
/// Receives audit events from `rx`, looks up matching subscriptions in
/// `engine`, and delivers them with retry logic. Stops when `rx` is closed
/// or a shutdown signal is received via `shutdown`.
pub async fn run_dispatcher(
    engine: Arc<dyn WebhookEngine>,
    clock: Arc<dyn Clock>,
    mut rx: AuditEventReceiver,
    mut shutdown: tokio::sync::watch::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => dispatch_event(Arc::clone(&engine), Arc::clone(&clock), event).await,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("webhook dispatcher lagged, skipped {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("webhook audit channel closed, dispatcher exiting");
                        return;
                    }
                }
            }
            _ = shutdown.changed() => {
                debug!("webhook dispatcher received shutdown signal");
                return;
            }
        }
    }
}

/// Finds matching subscriptions and spawns a delivery task for each one.
async fn dispatch_event(engine: Arc<dyn WebhookEngine>, clock: Arc<dyn Clock>, event: AuditEvent) {
    let query = WebhookQuery {
        realm_id: event.realm_id.clone(),
        enabled_only: true,
    };

    let subs = match engine.list(&query) {
        Ok(s) => s,
        Err(e) => {
            error!("failed to list webhook subscriptions for dispatch: {e}");
            return;
        }
    };

    for sub in subs {
        if !sub.matches(&event.action) {
            continue;
        }

        let eng = Arc::clone(&engine);
        let clk = Arc::clone(&clock);
        let ev = event.clone();
        tokio::spawn(async move {
            deliver_with_retry(eng, clk, sub, ev).await;
        });
    }
}

/// Delivers an event to a single subscription with exponential backoff.
async fn deliver_with_retry(
    engine: Arc<dyn WebhookEngine>,
    clock: Arc<dyn Clock>,
    sub: super::types::WebhookSubscription,
    event: AuditEvent,
) {
    let body = match serde_json::to_vec(&event) {
        Ok(b) => b,
        Err(e) => {
            error!("failed to serialize audit event for webhook delivery: {e}");
            return;
        }
    };

    for attempt in 0..MAX_DELIVERY_ATTEMPTS {
        let delay = BACKOFF_SECONDS[attempt as usize];
        if delay > 0 {
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        let delivery_id = WebhookDeliveryId::generate();
        let signature = sign_body(&sub.secret, &body);
        let event_type = event.action.as_str().to_string();
        let delivery_id_str = delivery_id.to_string();
        let url = sub.url.clone();
        let body_clone = body.clone();

        // ureq is a blocking client; run it on the blocking thread pool.
        let result = tokio::task::spawn_blocking(move || {
            deliver_once(&url, &body_clone, &signature, &event_type, &delivery_id_str)
        })
        .await;

        let now = clock.now();
        let outcome = match result {
            Ok(inner) => inner,
            Err(join_err) => Err(format!("spawn_blocking panic: {join_err}")),
        };

        match outcome {
            Ok(status_code) => {
                let delivery = make_delivery(
                    sub.id.clone(),
                    sub.realm_id.clone(),
                    event.id.clone(),
                    attempt + 1,
                    DeliveryStatus::Success,
                    Some(status_code),
                    None,
                    now,
                );
                if let Err(e) = engine.record_delivery(&delivery) {
                    error!("failed to record successful webhook delivery: {e}");
                }
                debug!(
                    webhook_id = %sub.id,
                    event_id = %event.id,
                    attempt = attempt + 1,
                    "webhook delivered successfully"
                );
                return;
            }
            Err(err_msg) => {
                let is_last = attempt + 1 == MAX_DELIVERY_ATTEMPTS;
                let delivery = make_delivery(
                    sub.id.clone(),
                    sub.realm_id.clone(),
                    event.id.clone(),
                    attempt + 1,
                    DeliveryStatus::Failed,
                    None,
                    Some(err_msg.clone()),
                    now,
                );
                if let Err(e) = engine.record_delivery(&delivery) {
                    error!("failed to record failed webhook delivery: {e}");
                }

                if is_last {
                    warn!(
                        webhook_id = %sub.id,
                        event_id = %event.id,
                        "webhook delivery exhausted all {MAX_DELIVERY_ATTEMPTS} attempts: {err_msg}"
                    );
                } else {
                    debug!(
                        webhook_id = %sub.id,
                        event_id = %event.id,
                        attempt = attempt + 1,
                        "webhook delivery attempt failed, will retry: {err_msg}"
                    );
                }
            }
        }
    }
}

/// Performs a single HTTP POST delivery.
///
/// Returns `Ok(status_code)` for 2xx responses, `Err(message)` otherwise.
/// Intended to be called inside `spawn_blocking`.
fn deliver_once(
    url: &str,
    body: &[u8],
    signature: &str,
    event_type: &str,
    delivery_id: &str,
) -> Result<u16, String> {
    let req = ureq::post(url)
        .header("Content-Type", "application/json")
        .header("X-Hearth-Signature-256", signature)
        .header("X-Hearth-Event", event_type)
        .header("X-Hearth-Delivery", delivery_id);

    let response = req.send(body).map_err(|e| format!("HTTP error: {e}"))?;

    let status: u16 = response.status().into();
    if (200..300).contains(&status) {
        Ok(status)
    } else {
        Err(format!("non-2xx response: {status}"))
    }
}

/// Computes `sha256=<hex(HMAC-SHA256(secret, body))>`.
fn sign_body(secret: &str, body: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let result = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_body_format() {
        let sig = sign_body("my-secret", b"hello");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 7 + 64); // "sha256=" + 64 hex chars
    }

    #[test]
    fn sign_body_deterministic() {
        let sig1 = sign_body("secret", b"payload");
        let sig2 = sign_body("secret", b"payload");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_body_differs_by_key() {
        let sig1 = sign_body("key1", b"payload");
        let sig2 = sign_body("key2", b"payload");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_body_differs_by_payload() {
        let sig1 = sign_body("key", b"payload1");
        let sig2 = sign_body("key", b"payload2");
        assert_ne!(sig1, sig2);
    }
}
