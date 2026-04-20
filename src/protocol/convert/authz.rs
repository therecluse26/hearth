//! Authorization type conversions: domain <-> proto wire types.

use crate::authz::{self as domain};
use crate::protocol::proto::authz::v1 as pb;

// ==================== ObjectRef ====================

impl From<&domain::ObjectRef> for pb::ObjectRef {
    fn from(o: &domain::ObjectRef) -> Self {
        Self {
            object_type: o.object_type().to_string(),
            object_id: o.object_id().to_string(),
        }
    }
}

// ==================== SubjectRef ====================

impl From<&domain::SubjectRef> for pb::SubjectRef {
    fn from(s: &domain::SubjectRef) -> Self {
        match s {
            domain::SubjectRef::Direct(obj) => Self {
                kind: Some(pb::subject_ref::Kind::Direct(pb::ObjectRef::from(obj))),
            },
            domain::SubjectRef::Userset { object, relation } => Self {
                kind: Some(pb::subject_ref::Kind::Userset(pb::UsersetRef {
                    object: Some(pb::ObjectRef::from(object)),
                    relation: relation.clone(),
                })),
            },
        }
    }
}

// ==================== RelationshipTuple ====================

impl From<&domain::RelationshipTuple> for pb::RelationshipTuple {
    fn from(t: &domain::RelationshipTuple) -> Self {
        Self {
            object: Some(pb::ObjectRef::from(&t.object)),
            relation: t.relation.clone(),
            subject: Some(pb::SubjectRef::from(&t.subject)),
        }
    }
}

// ==================== ConsistencyToken ====================

impl From<domain::ConsistencyToken> for pb::ConsistencyToken {
    fn from(t: domain::ConsistencyToken) -> Self {
        Self {
            version: t.version(),
        }
    }
}

// ==================== TupleChangeAction ====================

impl From<&domain::TupleChangeAction> for pb::TupleChangeAction {
    fn from(a: &domain::TupleChangeAction) -> Self {
        match a {
            domain::TupleChangeAction::Touch => Self::Touch,
            domain::TupleChangeAction::Delete => Self::Delete,
        }
    }
}

// ==================== TupleChangeEvent ====================

impl From<&domain::TupleChangeEvent> for pb::TupleChangeEvent {
    fn from(e: &domain::TupleChangeEvent) -> Self {
        Self {
            sequence: e.sequence,
            action: pb::TupleChangeAction::from(&e.action).into(),
            object_type: e.object_type.clone(),
            object_id: e.object_id.clone(),
            relation: e.relation.clone(),
            subject: e.subject.clone(),
            realm_id: e.realm_id.clone(),
            timestamp_us: e.timestamp_us,
        }
    }
}

// ==================== NamespaceConfig ====================

impl From<&domain::NamespaceConfig> for pb::NamespaceConfig {
    fn from(c: &domain::NamespaceConfig) -> Self {
        Self {
            object_types: c
                .object_types
                .iter()
                .map(|(k, v)| (k.clone(), pb::ObjectTypeConfig::from(v)))
                .collect(),
        }
    }
}

impl From<&domain::ObjectTypeConfig> for pb::ObjectTypeConfig {
    fn from(c: &domain::ObjectTypeConfig) -> Self {
        Self {
            relations: c
                .relations
                .iter()
                .map(|(k, v)| (k.clone(), pb::RelationConfig::from(v)))
                .collect(),
        }
    }
}

impl From<&domain::RelationConfig> for pb::RelationConfig {
    fn from(c: &domain::RelationConfig) -> Self {
        Self {
            allowed_subject_types: c.allowed_subject_types.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_ref_conversion() {
        let obj = domain::ObjectRef::new("document", "readme").expect("valid");
        let proto = pb::ObjectRef::from(&obj);
        assert_eq!(proto.object_type, "document");
        assert_eq!(proto.object_id, "readme");
    }

    #[test]
    fn subject_ref_direct_conversion() {
        let subj = domain::SubjectRef::direct("user", "alice").expect("valid");
        let proto = pb::SubjectRef::from(&subj);
        match proto.kind {
            Some(pb::subject_ref::Kind::Direct(obj)) => {
                assert_eq!(obj.object_type, "user");
                assert_eq!(obj.object_id, "alice");
            }
            _ => panic!("expected Direct variant"),
        }
    }

    #[test]
    fn subject_ref_userset_conversion() {
        let subj = domain::SubjectRef::userset("group", "eng", "member").expect("valid");
        let proto = pb::SubjectRef::from(&subj);
        match proto.kind {
            Some(pb::subject_ref::Kind::Userset(uset)) => {
                let obj = uset.object.expect("object present");
                assert_eq!(obj.object_type, "group");
                assert_eq!(obj.object_id, "eng");
                assert_eq!(uset.relation, "member");
            }
            _ => panic!("expected Userset variant"),
        }
    }

    #[test]
    fn consistency_token_conversion() {
        let token = domain::ConsistencyToken::new(42);
        let proto = pb::ConsistencyToken::from(token);
        assert_eq!(proto.version, 42);
    }
}
