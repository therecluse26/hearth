//! Storage key encoding and decoding for authorization tuples.
//!
//! Two indexes are maintained, both realm-scoped via `StorageEngine`:
//!
//! - **Forward**: `fwd:{type}:{id}#{relation}@{subject}` — for `check()` and `expand()`
//! - **Reverse**: `rev:{subject}@{type}:{id}#{relation}` — for reverse lookups and `watch()`

use crate::authz::error::AuthzError;
use crate::authz::types::{ObjectRef, SubjectRef};

/// Marker byte stored as the value for each tuple key (presence-only).
pub(crate) const PRESENCE_MARKER: &[u8] = &[0x01];

/// Forward index prefix.
const FWD_PREFIX: &str = "fwd:";
/// Reverse index prefix.
const REV_PREFIX: &str = "rev:";
/// Key for namespace configuration.
const NAMESPACE_CONFIG_KEY: &[u8] = b"ns:config";
/// Prefix for watch event keys.
const WATCH_EVT_PREFIX: &str = "watch:evt:";

/// Encodes a subject reference to its string form for key embedding.
fn encode_subject(subject: &SubjectRef) -> String {
    match subject {
        SubjectRef::Direct(obj) => format!("{}:{}", obj.object_type(), obj.object_id()),
        SubjectRef::Userset { object, relation } => {
            format!(
                "{}:{}#{}",
                object.object_type(),
                object.object_id(),
                relation
            )
        }
    }
}

/// Encodes the forward index key for a complete tuple.
///
/// Format: `fwd:{type}:{id}#{relation}@{subject}`
pub(crate) fn encode_forward(object: &ObjectRef, relation: &str, subject: &SubjectRef) -> Vec<u8> {
    format!(
        "{FWD_PREFIX}{}:{}#{relation}@{}",
        object.object_type(),
        object.object_id(),
        encode_subject(subject)
    )
    .into_bytes()
}

/// Encodes the forward index prefix for scanning all subjects of an (object, relation).
///
/// Format: `fwd:{type}:{id}#{relation}@`
pub(crate) fn encode_forward_prefix(object: &ObjectRef, relation: &str) -> Vec<u8> {
    format!(
        "{FWD_PREFIX}{}:{}#{relation}@",
        object.object_type(),
        object.object_id()
    )
    .into_bytes()
}

/// Computes the exclusive end bound for a prefix scan.
///
/// Increments the last byte of the prefix. This works because all valid
/// key characters are ASCII and `@` (0x40) incremented to `A` (0x41)
/// is still lexicographically greater than any valid subject encoding.
pub(crate) fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Encodes the reverse index key for a complete tuple.
///
/// Format: `rev:{subject}@{type}:{id}#{relation}`
pub(crate) fn encode_reverse(object: &ObjectRef, relation: &str, subject: &SubjectRef) -> Vec<u8> {
    format!(
        "{REV_PREFIX}{}@{}:{}#{relation}",
        encode_subject(subject),
        object.object_type(),
        object.object_id()
    )
    .into_bytes()
}

/// Encodes the reverse-index scan prefix for a given subject.
///
/// Returned bytes match every reverse-index key with that subject, so a
/// storage scan over `[prefix, prefix_end(prefix))` enumerates every
/// `(object, relation)` pair the subject appears in.
///
/// Format: `rev:{subject}@`
pub(crate) fn encode_reverse_prefix_for_subject(subject: &SubjectRef) -> Vec<u8> {
    format!("{REV_PREFIX}{}@", encode_subject(subject)).into_bytes()
}

/// Parses a reverse-index key into its `(object_type, object_id, relation)`
/// triple. Returns `None` if the key does not follow the `rev:{subject}@{type}:{id}#{rel}`
/// shape. Used when scanning all tuples attached to a subject.
pub(crate) fn decode_reverse_tail(
    key: &[u8],
    subject_prefix: &[u8],
) -> Option<(String, String, String)> {
    let rest = key.strip_prefix(subject_prefix)?;
    let rest = std::str::from_utf8(rest).ok()?;
    // rest is `{type}:{id}#{relation}`
    let (object_type, after_type) = rest.split_once(':')?;
    let (object_id, relation) = after_type.split_once('#')?;
    Some((
        object_type.to_string(),
        object_id.to_string(),
        relation.to_string(),
    ))
}

/// Returns the storage key for the namespace configuration.
pub(crate) fn encode_namespace_config() -> &'static [u8] {
    NAMESPACE_CONFIG_KEY
}

/// Encodes a watch event key with zero-padded sequence and event index.
///
/// Format: `watch:evt:{sequence:020}:{index:05}` — zero-padded for
/// lexicographic ordering. Multiple events in a single `write_tuples`
/// batch share the same sequence but have different indexes.
pub(crate) fn encode_watch_event(sequence: u64, index: u32) -> Vec<u8> {
    format!("{WATCH_EVT_PREFIX}{sequence:020}:{index:05}").into_bytes()
}

/// Returns the prefix for scanning all watch events.
pub(crate) fn encode_watch_event_prefix() -> &'static [u8] {
    WATCH_EVT_PREFIX.as_bytes()
}

/// Decoded subject from a forward index scan entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodedSubject {
    /// A direct subject: `type:id`
    Direct {
        /// Subject object type.
        object_type: String,
        /// Subject object ID.
        object_id: String,
    },
    /// A userset subject: `type:id#relation`
    Userset {
        /// Userset object type.
        object_type: String,
        /// Userset object ID.
        object_id: String,
        /// Userset relation.
        relation: String,
    },
}

impl DecodedSubject {
    /// Converts this decoded subject into a `SubjectRef`.
    ///
    /// # Errors
    ///
    /// Returns `AuthzError::InvalidReference` if the decoded values fail validation.
    pub(crate) fn into_subject_ref(self) -> Result<SubjectRef, AuthzError> {
        match self {
            Self::Direct {
                object_type,
                object_id,
            } => SubjectRef::direct(&object_type, &object_id),
            Self::Userset {
                object_type,
                object_id,
                relation,
            } => SubjectRef::userset(&object_type, &object_id, &relation),
        }
    }
}

/// Decodes a subject string from the portion after `@` in a forward key.
///
/// Handles both `type:id` (direct) and `type:id#relation` (userset) forms.
pub(crate) fn decode_subject_from_key(subject_str: &str) -> Result<DecodedSubject, AuthzError> {
    // Check for userset: type:id#relation
    if let Some(hash_pos) = subject_str.rfind('#') {
        let before_hash = &subject_str[..hash_pos];
        let relation = &subject_str[hash_pos + 1..];

        let colon_pos = before_hash
            .find(':')
            .ok_or_else(|| AuthzError::InvalidTuple {
                reason: format!("malformed subject in key: missing ':' in '{subject_str}'"),
            })?;
        let object_type = &before_hash[..colon_pos];
        let object_id = &before_hash[colon_pos + 1..];

        Ok(DecodedSubject::Userset {
            object_type: object_type.to_string(),
            object_id: object_id.to_string(),
            relation: relation.to_string(),
        })
    } else {
        // Direct: type:id
        let colon_pos = subject_str
            .find(':')
            .ok_or_else(|| AuthzError::InvalidTuple {
                reason: format!("malformed subject in key: missing ':' in '{subject_str}'"),
            })?;
        let object_type = &subject_str[..colon_pos];
        let object_id = &subject_str[colon_pos + 1..];

        Ok(DecodedSubject::Direct {
            object_type: object_type.to_string(),
            object_id: object_id.to_string(),
        })
    }
}

/// Extracts the subject portion from a forward index key's raw bytes.
///
/// Given a scan entry key, strips the forward prefix and returns the
/// substring after the `@` separator.
pub(crate) fn extract_subject_from_forward_key(
    key: &[u8],
    prefix: &[u8],
) -> Result<DecodedSubject, AuthzError> {
    let key_str = std::str::from_utf8(key).map_err(|_| AuthzError::InvalidTuple {
        reason: "non-UTF-8 key in forward index".to_string(),
    })?;

    let prefix_str = std::str::from_utf8(prefix).map_err(|_| AuthzError::InvalidTuple {
        reason: "non-UTF-8 prefix".to_string(),
    })?;

    let subject_str = key_str
        .strip_prefix(prefix_str)
        .ok_or_else(|| AuthzError::InvalidTuple {
            reason: format!("key does not start with expected prefix: '{key_str}'"),
        })?;

    decode_subject_from_key(subject_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_key_direct_subject() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let key = encode_forward(&obj, "viewer", &subj);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "fwd:document:readme#viewer@user:alice");
    }

    #[test]
    fn forward_key_userset_subject() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::userset("group", "eng", "member").expect("valid");
        let key = encode_forward(&obj, "viewer", &subj);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "fwd:document:readme#viewer@group:eng#member");
    }

    #[test]
    fn reverse_key_direct_subject() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let key = encode_reverse(&obj, "viewer", &subj);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "rev:user:alice@document:readme#viewer");
    }

    #[test]
    fn reverse_key_userset_subject() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::userset("group", "eng", "member").expect("valid");
        let key = encode_reverse(&obj, "viewer", &subj);
        let key_str = std::str::from_utf8(&key).expect("utf8");
        assert_eq!(key_str, "rev:group:eng#member@document:readme#viewer");
    }

    #[test]
    fn forward_prefix_encoding() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let prefix = encode_forward_prefix(&obj, "viewer");
        let prefix_str = std::str::from_utf8(&prefix).expect("utf8");
        assert_eq!(prefix_str, "fwd:document:readme#viewer@");
    }

    #[test]
    fn prefix_end_increments_last_byte() {
        let prefix = b"fwd:document:readme#viewer@";
        let end = prefix_end(prefix);
        // '@' is 0x40, incrementing gives 'A' (0x41)
        assert_eq!(end.last(), Some(&0x41));
        assert!(end > prefix.to_vec());
    }

    #[test]
    fn prefix_end_empty_input() {
        let end = prefix_end(b"");
        assert!(end.is_empty());
    }

    #[test]
    fn decode_subject_direct_roundtrip() {
        let decoded = decode_subject_from_key("user:alice").expect("valid");
        assert_eq!(
            decoded,
            DecodedSubject::Direct {
                object_type: "user".to_string(),
                object_id: "alice".to_string(),
            }
        );
    }

    #[test]
    fn decode_subject_userset_roundtrip() {
        let decoded = decode_subject_from_key("group:eng#member").expect("valid");
        assert_eq!(
            decoded,
            DecodedSubject::Userset {
                object_type: "group".to_string(),
                object_id: "eng".to_string(),
                relation: "member".to_string(),
            }
        );
    }

    #[test]
    fn decode_subject_missing_colon_fails() {
        let err = decode_subject_from_key("useralice").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidTuple { .. }));
    }

    #[test]
    fn extract_subject_from_full_key() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let key = encode_forward(&obj, "viewer", &subj);
        let prefix = encode_forward_prefix(&obj, "viewer");

        let decoded = extract_subject_from_forward_key(&key, &prefix).expect("valid");
        assert_eq!(
            decoded,
            DecodedSubject::Direct {
                object_type: "user".to_string(),
                object_id: "alice".to_string(),
            }
        );
    }

    #[test]
    fn extract_subject_userset_from_full_key() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::userset("group", "eng", "member").expect("valid");
        let key = encode_forward(&obj, "viewer", &subj);
        let prefix = encode_forward_prefix(&obj, "viewer");

        let decoded = extract_subject_from_forward_key(&key, &prefix).expect("valid");
        assert_eq!(
            decoded,
            DecodedSubject::Userset {
                object_type: "group".to_string(),
                object_id: "eng".to_string(),
                relation: "member".to_string(),
            }
        );
    }

    #[test]
    fn decoded_subject_into_subject_ref_direct() {
        let decoded = DecodedSubject::Direct {
            object_type: "user".to_string(),
            object_id: "alice".to_string(),
        };
        let subject = decoded.into_subject_ref().expect("valid");
        assert!(matches!(subject, SubjectRef::Direct(_)));
        assert_eq!(format!("{subject}"), "user:alice");
    }

    #[test]
    fn decoded_subject_into_subject_ref_userset() {
        let decoded = DecodedSubject::Userset {
            object_type: "group".to_string(),
            object_id: "eng".to_string(),
            relation: "member".to_string(),
        };
        let subject = decoded.into_subject_ref().expect("valid");
        assert!(matches!(subject, SubjectRef::Userset { .. }));
        assert_eq!(format!("{subject}"), "group:eng#member");
    }

    #[test]
    fn forward_and_reverse_keys_differ() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let fwd = encode_forward(&obj, "viewer", &subj);
        let rev = encode_reverse(&obj, "viewer", &subj);
        assert_ne!(fwd, rev);
    }

    #[test]
    fn forward_key_prefix_is_prefix_of_full_key() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let key = encode_forward(&obj, "viewer", &subj);
        let prefix = encode_forward_prefix(&obj, "viewer");
        assert!(key.starts_with(&prefix));
    }
}
