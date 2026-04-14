//! Zanzibar-style authorization types.
//!
//! Implements the core data model: `(object#relation@subject)` tuples
//! where subjects can be direct references or usersets.

use crate::authz::error::AuthzError;

/// Maximum length for object type and ID fields.
const MAX_TYPE_ID_LEN: usize = 128;
/// Maximum length for relation fields.
const MAX_RELATION_LEN: usize = 64;
/// Characters forbidden in type, ID, and relation fields (used as delimiters).
const DELIMITER_CHARS: &[char] = &[':', '#', '@'];

/// Validates that a string contains only ASCII alphanumeric, `_`, or `-` characters,
/// does not contain delimiter characters, and is within the given length limit.
fn validate_field(value: &str, field_name: &str, max_len: usize) -> Result<(), AuthzError> {
    if value.is_empty() {
        return Err(AuthzError::InvalidReference {
            reason: format!("{field_name} must not be empty"),
        });
    }
    if value.len() > max_len {
        return Err(AuthzError::InvalidReference {
            reason: format!(
                "{field_name} exceeds maximum length of {max_len}: got {}",
                value.len()
            ),
        });
    }
    if value.contains(DELIMITER_CHARS) {
        return Err(AuthzError::InvalidReference {
            reason: format!("{field_name} must not contain delimiter characters (:, #, @)"),
        });
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AuthzError::InvalidReference {
            reason: format!(
                "{field_name} must contain only ASCII alphanumeric, underscore, or hyphen characters"
            ),
        });
    }
    Ok(())
}

/// Validates a relation field (ASCII alphanumeric + `_`, max 64 chars).
fn validate_relation(value: &str) -> Result<(), AuthzError> {
    if value.is_empty() {
        return Err(AuthzError::InvalidTuple {
            reason: "relation must not be empty".to_string(),
        });
    }
    if value.len() > MAX_RELATION_LEN {
        return Err(AuthzError::InvalidTuple {
            reason: format!(
                "relation exceeds maximum length of {MAX_RELATION_LEN}: got {}",
                value.len()
            ),
        });
    }
    if value.contains(DELIMITER_CHARS) {
        return Err(AuthzError::InvalidTuple {
            reason: "relation must not contain delimiter characters (:, #, @)".to_string(),
        });
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(AuthzError::InvalidTuple {
            reason: "relation must contain only ASCII alphanumeric or underscore characters"
                .to_string(),
        });
    }
    Ok(())
}

/// A reference to an object: `{type}:{id}` (e.g., `document:readme`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectRef {
    /// The object type (e.g., `document`, `folder`, `group`).
    object_type: String,
    /// The object identifier (e.g., `readme`, `eng-team`).
    object_id: String,
}

impl ObjectRef {
    /// Creates a new `ObjectRef` with validation.
    ///
    /// # Errors
    ///
    /// Returns `AuthzError::InvalidReference` if type or id are empty,
    /// exceed 128 characters, or contain forbidden characters.
    pub fn new(object_type: &str, object_id: &str) -> Result<Self, AuthzError> {
        validate_field(object_type, "object_type", MAX_TYPE_ID_LEN)?;
        validate_field(object_id, "object_id", MAX_TYPE_ID_LEN)?;
        Ok(Self {
            object_type: object_type.to_string(),
            object_id: object_id.to_string(),
        })
    }

    /// Returns the object type.
    pub fn object_type(&self) -> &str {
        &self.object_type
    }

    /// Returns the object ID.
    pub fn object_id(&self) -> &str {
        &self.object_id
    }
}

impl std::fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.object_type, self.object_id)
    }
}

/// A reference to a subject: either a direct entity or a userset.
///
/// - `Direct(ObjectRef)`: e.g., `user:alice`
/// - `Userset { object, relation }`: e.g., `group:eng#member`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubjectRef {
    /// A direct entity reference (e.g., `user:alice`).
    Direct(ObjectRef),
    /// A userset reference (e.g., `group:eng#member` — all members of group eng).
    Userset {
        /// The object the userset belongs to.
        object: ObjectRef,
        /// The relation within that object.
        relation: String,
    },
}

impl SubjectRef {
    /// Creates a direct subject reference.
    ///
    /// # Errors
    ///
    /// Returns `AuthzError::InvalidReference` if the object ref is invalid.
    pub fn direct(object_type: &str, object_id: &str) -> Result<Self, AuthzError> {
        Ok(Self::Direct(ObjectRef::new(object_type, object_id)?))
    }

    /// Creates a userset subject reference.
    ///
    /// # Errors
    ///
    /// Returns `AuthzError::InvalidReference` or `AuthzError::InvalidTuple` if
    /// the object ref or relation is invalid.
    pub fn userset(object_type: &str, object_id: &str, relation: &str) -> Result<Self, AuthzError> {
        validate_relation(relation)?;
        Ok(Self::Userset {
            object: ObjectRef::new(object_type, object_id)?,
            relation: relation.to_string(),
        })
    }
}

impl std::fmt::Display for SubjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(obj) => write!(f, "{obj}"),
            Self::Userset { object, relation } => write!(f, "{object}#{relation}"),
        }
    }
}

/// A complete relationship tuple: `(object#relation@subject)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipTuple {
    /// The object being related.
    pub object: ObjectRef,
    /// The relation type (e.g., `viewer`, `editor`, `member`).
    pub relation: String,
    /// The subject of the relation.
    pub subject: SubjectRef,
}

impl RelationshipTuple {
    /// Creates a new relationship tuple with validation.
    ///
    /// # Errors
    ///
    /// Returns `AuthzError::InvalidTuple` if the relation is invalid.
    pub fn new(object: ObjectRef, relation: &str, subject: SubjectRef) -> Result<Self, AuthzError> {
        validate_relation(relation)?;
        Ok(Self {
            object,
            relation: relation.to_string(),
            subject,
        })
    }
}

impl std::fmt::Display for RelationshipTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}@{}", self.object, self.relation, self.subject)
    }
}

/// A write operation on a relationship tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TupleWrite {
    /// Add a relationship tuple.
    Touch(RelationshipTuple),
    /// Remove a relationship tuple.
    Delete(RelationshipTuple),
}

/// Filter for the `watch()` operation (stub for Phase 1+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchFilter {
    /// Optional object type to filter on.
    pub object_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== ObjectRef =====

    #[test]
    fn object_ref_valid() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        assert_eq!(obj.object_type(), "document");
        assert_eq!(obj.object_id(), "readme");
        assert_eq!(format!("{obj}"), "document:readme");
    }

    #[test]
    fn object_ref_with_underscore_and_hyphen() {
        let obj = ObjectRef::new("my_type", "my-id-123").expect("valid");
        assert_eq!(obj.object_type(), "my_type");
        assert_eq!(obj.object_id(), "my-id-123");
    }

    #[test]
    fn object_ref_empty_type_rejected() {
        let err = ObjectRef::new("", "id").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));
    }

    #[test]
    fn object_ref_empty_id_rejected() {
        let err = ObjectRef::new("type", "").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));
    }

    #[test]
    fn object_ref_delimiter_in_type_rejected() {
        let err = ObjectRef::new("doc:ument", "id").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));
    }

    #[test]
    fn object_ref_delimiter_in_id_rejected() {
        let err = ObjectRef::new("doc", "id#1").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));

        let err = ObjectRef::new("doc", "id@1").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));
    }

    #[test]
    fn object_ref_oversized_type_rejected() {
        let long_type = "a".repeat(129);
        let err = ObjectRef::new(&long_type, "id").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));
    }

    #[test]
    fn object_ref_oversized_id_rejected() {
        let long_id = "b".repeat(129);
        let err = ObjectRef::new("type", &long_id).expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));
    }

    #[test]
    fn object_ref_max_length_accepted() {
        let max_str = "a".repeat(128);
        let obj = ObjectRef::new(&max_str, &max_str).expect("128 chars should be valid");
        assert_eq!(obj.object_type().len(), 128);
    }

    #[test]
    fn object_ref_non_ascii_rejected() {
        let err = ObjectRef::new("type", "idé").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));
    }

    #[test]
    fn object_ref_space_rejected() {
        let err = ObjectRef::new("type", "id with space").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidReference { .. }));
    }

    // ===== SubjectRef =====

    #[test]
    fn subject_ref_direct() {
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        assert_eq!(format!("{subj}"), "user:alice");
        assert!(matches!(subj, SubjectRef::Direct(_)));
    }

    #[test]
    fn subject_ref_userset() {
        let subj = SubjectRef::userset("group", "eng", "member").expect("valid");
        assert_eq!(format!("{subj}"), "group:eng#member");
        assert!(matches!(subj, SubjectRef::Userset { .. }));
    }

    #[test]
    fn subject_ref_userset_invalid_relation() {
        let err = SubjectRef::userset("group", "eng", "").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidTuple { .. }));
    }

    #[test]
    fn subject_ref_userset_relation_with_hyphen_rejected() {
        // Relations allow only alphanumeric + underscore (no hyphens)
        let err = SubjectRef::userset("group", "eng", "mem-ber").expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidTuple { .. }));
    }

    // ===== RelationshipTuple =====

    #[test]
    fn relationship_tuple_valid() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("valid");
        assert_eq!(format!("{tuple}"), "document:readme#viewer@user:alice");
    }

    #[test]
    fn relationship_tuple_empty_relation_rejected() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let err = RelationshipTuple::new(obj, "", subj).expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidTuple { .. }));
    }

    #[test]
    fn relationship_tuple_oversized_relation_rejected() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let long_rel = "a".repeat(65);
        let err = RelationshipTuple::new(obj, &long_rel, subj).expect_err("should fail");
        assert!(matches!(err, AuthzError::InvalidTuple { .. }));
    }

    #[test]
    fn relationship_tuple_max_relation_accepted() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let max_rel = "a".repeat(64);
        let tuple = RelationshipTuple::new(obj, &max_rel, subj).expect("64 chars should be valid");
        assert_eq!(tuple.relation.len(), 64);
    }

    #[test]
    fn relationship_tuple_with_userset_subject() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::userset("group", "eng", "member").expect("valid");
        let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("valid");
        assert_eq!(
            format!("{tuple}"),
            "document:readme#viewer@group:eng#member"
        );
    }

    // ===== TupleWrite =====

    #[test]
    fn tuple_write_touch_and_delete() {
        let obj = ObjectRef::new("document", "readme").expect("valid");
        let subj = SubjectRef::direct("user", "alice").expect("valid");
        let tuple = RelationshipTuple::new(obj, "viewer", subj).expect("valid");

        let touch = TupleWrite::Touch(tuple.clone());
        assert!(matches!(touch, TupleWrite::Touch(_)));

        let delete = TupleWrite::Delete(tuple);
        assert!(matches!(delete, TupleWrite::Delete(_)));
    }

    // ===== WatchFilter =====

    #[test]
    fn watch_filter_construction() {
        let filter = WatchFilter {
            object_type: Some("document".to_string()),
        };
        assert_eq!(filter.object_type.as_deref(), Some("document"));

        let empty_filter = WatchFilter { object_type: None };
        assert!(empty_filter.object_type.is_none());
    }
}
