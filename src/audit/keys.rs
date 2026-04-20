//! Storage key encoding for audit log records.
//!
//! Audit events are stored with time-ordered keys for efficient range scans.
//! All keys are realm-scoped via the `StorageEngine`'s `RealmId` requirement.
//!
//! Indexes maintained:
//!
//! - **Event primary**: `audit:evt:{timestamp_19d}:{uuid}` → JSON-serialized `AuditEvent`
//! - **Actor index**: `audit:actor:{actor}:{timestamp_19d}:{uuid}` → event primary key
//! - **Action index**: `audit:action:{action}:{timestamp_19d}:{uuid}` → event primary key
//!
//! Timestamps are zero-padded to 19 digits for correct lexicographic ordering.

use crate::core::{AuditEventId, Timestamp};

/// Prefix for audit event primary keys.
const EVENT_PREFIX: &str = "audit:evt:";

/// Prefix for audit actor index keys.
const ACTOR_PREFIX: &str = "audit:actor:";

/// Prefix for audit action index keys.
const ACTION_PREFIX: &str = "audit:action:";

/// Formats a timestamp as a 19-digit zero-padded string.
///
/// This ensures lexicographic ordering matches chronological ordering
/// for all positive timestamp values.
fn pad_timestamp(ts: Timestamp) -> String {
    format!("{:019}", ts.as_micros())
}

/// Encodes the primary key for an audit event.
///
/// Format: `audit:evt:{timestamp_19d}:{uuid}`
pub(crate) fn encode_event_key(timestamp: Timestamp, event_id: &AuditEventId) -> Vec<u8> {
    format!(
        "{EVENT_PREFIX}{}:{}",
        pad_timestamp(timestamp),
        event_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all audit events (used with time-range filtering).
///
/// Format: `audit:evt:`
pub(crate) fn event_scan_prefix() -> Vec<u8> {
    EVENT_PREFIX.as_bytes().to_vec()
}

/// Returns the scan start key for events at or after a given timestamp.
///
/// Format: `audit:evt:{timestamp_19d}`
pub(crate) fn event_scan_start(timestamp: Timestamp) -> Vec<u8> {
    format!("{EVENT_PREFIX}{}", pad_timestamp(timestamp)).into_bytes()
}

/// Returns the scan end key for events before a given timestamp (exclusive).
///
/// Format: `audit:evt:{timestamp_19d}`
pub(crate) fn event_scan_end(timestamp: Timestamp) -> Vec<u8> {
    format!("{EVENT_PREFIX}{}", pad_timestamp(timestamp)).into_bytes()
}

/// Encodes the actor index key for an audit event.
///
/// Format: `audit:actor:{actor}:{timestamp_19d}:{uuid}`
pub(crate) fn encode_actor_index(
    actor: &str,
    timestamp: Timestamp,
    event_id: &AuditEventId,
) -> Vec<u8> {
    format!(
        "{ACTOR_PREFIX}{actor}:{}:{}",
        pad_timestamp(timestamp),
        event_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all events by a given actor.
///
/// Format: `audit:actor:{actor}:`
pub(crate) fn actor_scan_prefix(actor: &str) -> Vec<u8> {
    format!("{ACTOR_PREFIX}{actor}:").into_bytes()
}

/// Encodes the action index key for an audit event.
///
/// Format: `audit:action:{action}:{timestamp_19d}:{uuid}`
pub(crate) fn encode_action_index(
    action: &str,
    timestamp: Timestamp,
    event_id: &AuditEventId,
) -> Vec<u8> {
    format!(
        "{ACTION_PREFIX}{action}:{}:{}",
        pad_timestamp(timestamp),
        event_id.as_uuid()
    )
    .into_bytes()
}

/// Returns the scan prefix for all events of a given action type.
///
/// Format: `audit:action:{action}:`
pub(crate) fn action_scan_prefix(action: &str) -> Vec<u8> {
    format!("{ACTION_PREFIX}{action}:").into_bytes()
}

/// Computes the exclusive end bound for a prefix scan.
///
/// Increments the last byte of the prefix.
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
    use crate::core::AuditEventId;

    #[test]
    fn pad_timestamp_19_digits() {
        let ts = Timestamp::from_micros(1_700_000_000_000_000);
        let padded = pad_timestamp(ts);
        assert_eq!(padded.len(), 19);
        assert_eq!(padded, "0001700000000000000");
    }

    #[test]
    fn pad_timestamp_small_value() {
        let ts = Timestamp::from_micros(42);
        let padded = pad_timestamp(ts);
        assert_eq!(padded.len(), 19);
        assert_eq!(padded, "0000000000000000042");
    }

    #[test]
    fn encode_event_key_format() {
        let ts = Timestamp::from_micros(1_700_000_000_000_000);
        let id = AuditEventId::generate();
        let key = encode_event_key(ts, &id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("audit:evt:0001700000000000000:"));
        assert!(key_str.contains(&id.as_uuid().to_string()));
    }

    #[test]
    fn event_keys_ordered_by_timestamp() {
        let id1 = AuditEventId::generate();
        let id2 = AuditEventId::generate();
        let key1 = encode_event_key(Timestamp::from_micros(100), &id1);
        let key2 = encode_event_key(Timestamp::from_micros(200), &id2);
        assert!(key1 < key2, "earlier timestamp should sort first");
    }

    #[test]
    fn event_scan_prefix_format() {
        let prefix = event_scan_prefix();
        let prefix_str = std::str::from_utf8(&prefix).expect("utf8");
        assert_eq!(prefix_str, "audit:evt:");
    }

    #[test]
    fn event_key_starts_with_scan_prefix() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_event_key(ts, &id);
        let prefix = event_scan_prefix();
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_actor_index_format() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_actor_index("user_123", ts, &id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("audit:actor:user_123:"));
    }

    #[test]
    fn actor_index_starts_with_actor_prefix() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_actor_index("user_123", ts, &id);
        let prefix = actor_scan_prefix("user_123");
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn encode_action_index_format() {
        let ts = Timestamp::from_micros(1000);
        let id = AuditEventId::generate();
        let key = encode_action_index("user_created", ts, &id);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert!(key_str.starts_with("audit:action:user_created:"));
    }

    #[test]
    fn prefix_end_increments() {
        let prefix = event_scan_prefix();
        let end = prefix_end(&prefix);
        assert!(end > prefix);
    }

    #[test]
    fn different_actors_different_prefixes() {
        let p1 = actor_scan_prefix("alice");
        let p2 = actor_scan_prefix("bob");
        assert_ne!(p1, p2);
    }
}
