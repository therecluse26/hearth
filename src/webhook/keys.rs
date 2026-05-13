//! Storage key encoding for webhook subscriptions and delivery logs.
//!
//! Key layout:
//!
//! - **Subscription primary**: `wh:sub:{webhook_uuid}` → JSON `WebhookSubscription`
//! - **Delivery log**:         `wh:dlv:{webhook_uuid}:{timestamp_19d}:{delivery_uuid}` → JSON `WebhookDelivery`
//!
//! Both namespaces are realm-scoped via the storage engine's `RealmId` requirement.

use crate::core::{Timestamp, WebhookDeliveryId, WebhookId};

const SUB_PREFIX: &str = "wh:sub:";
const DLV_PREFIX: &str = "wh:dlv:";

fn pad_ts(ts: Timestamp) -> String {
    format!("{:019}", ts.as_micros())
}

/// Primary key for a webhook subscription.
///
/// Format: `wh:sub:{uuid}`
pub(crate) fn sub_key(id: &WebhookId) -> Vec<u8> {
    format!("{SUB_PREFIX}{}", id.as_uuid()).into_bytes()
}

/// Scan prefix for all subscriptions in a realm.
///
/// Format: `wh:sub:`
pub(crate) fn sub_scan_prefix() -> Vec<u8> {
    SUB_PREFIX.as_bytes().to_vec()
}

/// Primary key for a delivery log entry.
///
/// Format: `wh:dlv:{webhook_uuid}:{timestamp_19d}:{delivery_uuid}`
pub(crate) fn dlv_key(
    webhook_id: &WebhookId,
    ts: Timestamp,
    delivery_id: &WebhookDeliveryId,
) -> Vec<u8> {
    format!(
        "{DLV_PREFIX}{}:{}:{}",
        webhook_id.as_uuid(),
        pad_ts(ts),
        delivery_id.as_uuid()
    )
    .into_bytes()
}

/// Scan prefix for all delivery log entries for a specific webhook.
///
/// Format: `wh:dlv:{webhook_uuid}:`
pub(crate) fn dlv_scan_prefix_for_webhook(webhook_id: &WebhookId) -> Vec<u8> {
    format!("{DLV_PREFIX}{}:", webhook_id.as_uuid()).into_bytes()
}

/// Scan prefix for all delivery log entries in a realm.
///
/// Format: `wh:dlv:`
pub(crate) fn dlv_scan_prefix() -> Vec<u8> {
    DLV_PREFIX.as_bytes().to_vec()
}

/// Returns an exclusive end bound for a prefix scan.
pub(crate) fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_key_format() {
        let id = WebhookId::generate();
        let key = sub_key(&id);
        let s = std::str::from_utf8(&key).expect("valid utf8");
        assert!(s.starts_with("wh:sub:"));
        assert!(s.contains(&id.as_uuid().to_string()));
    }

    #[test]
    fn sub_key_starts_with_scan_prefix() {
        let id = WebhookId::generate();
        assert!(sub_key(&id).starts_with(&sub_scan_prefix()));
    }

    #[test]
    fn dlv_key_format() {
        let wid = WebhookId::generate();
        let did = WebhookDeliveryId::generate();
        let ts = Timestamp::from_micros(1_700_000_000_000_000);
        let key = dlv_key(&wid, ts, &did);
        let s = std::str::from_utf8(&key).expect("valid utf8");
        assert!(s.starts_with("wh:dlv:"));
        assert!(s.contains(&wid.as_uuid().to_string()));
        assert!(s.contains(&did.as_uuid().to_string()));
    }

    #[test]
    fn dlv_keys_ordered_by_timestamp() {
        let wid = WebhookId::generate();
        let did1 = WebhookDeliveryId::generate();
        let did2 = WebhookDeliveryId::generate();
        let k1 = dlv_key(&wid, Timestamp::from_micros(100), &did1);
        let k2 = dlv_key(&wid, Timestamp::from_micros(200), &did2);
        assert!(k1 < k2);
    }
}
