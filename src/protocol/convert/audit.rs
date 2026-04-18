//! Audit type conversions: domain <-> proto wire types.

use crate::audit::{self as domain};
use crate::protocol::proto::events::v1 as pb;

// ==================== AuditAction ====================

/// Converts domain `AuditAction` to proto enum value.
pub(crate) fn domain_audit_action_to_proto(a: &domain::AuditAction) -> pb::AuditAction {
    match a {
        domain::AuditAction::UserCreated => pb::AuditAction::UserCreated,
        domain::AuditAction::UserUpdated => pb::AuditAction::UserUpdated,
        domain::AuditAction::UserDeleted => pb::AuditAction::UserDeleted,
        domain::AuditAction::CredentialSet => pb::AuditAction::CredentialSet,
        domain::AuditAction::CredentialChanged => pb::AuditAction::CredentialChanged,
        domain::AuditAction::CredentialVerified => pb::AuditAction::CredentialVerified,
        domain::AuditAction::SessionCreated => pb::AuditAction::SessionCreated,
        domain::AuditAction::SessionRevoked => pb::AuditAction::SessionRevoked,
        domain::AuditAction::TokenIssued => pb::AuditAction::TokenIssued,
        domain::AuditAction::TokenRefreshed => pb::AuditAction::TokenRefreshed,
        domain::AuditAction::TenantCreated => pb::AuditAction::TenantCreated,
        domain::AuditAction::TenantUpdated => pb::AuditAction::TenantUpdated,
        domain::AuditAction::TenantDeleted => pb::AuditAction::TenantDeleted,
        domain::AuditAction::ClientRegistered => pb::AuditAction::ClientRegistered,
        domain::AuditAction::AuthorizationCodeIssued => pb::AuditAction::AuthorizationCodeIssued,
        domain::AuditAction::AuthorizationCodeExchanged => {
            pb::AuditAction::AuthorizationCodeExchanged
        }
        domain::AuditAction::TupleWritten => pb::AuditAction::TupleWritten,
        domain::AuditAction::TupleDeleted => pb::AuditAction::TupleDeleted,
        domain::AuditAction::ClientUpdated => pb::AuditAction::ClientUpdated,
        domain::AuditAction::ClientDeleted => pb::AuditAction::ClientDeleted,
        domain::AuditAction::BulkUsersCreated => pb::AuditAction::BulkUsersCreated,
        domain::AuditAction::BulkUsersDisabled => pb::AuditAction::BulkUsersDisabled,
        domain::AuditAction::OrgCreated => pb::AuditAction::OrgCreated,
        domain::AuditAction::OrgUpdated => pb::AuditAction::OrgUpdated,
        domain::AuditAction::OrgDeleted => pb::AuditAction::OrgDeleted,
    }
}

// ==================== AuditEvent ====================

impl From<&domain::AuditEvent> for pb::AuditEvent {
    fn from(e: &domain::AuditEvent) -> Self {
        Self {
            id: e.id.as_uuid().to_string(),
            tenant_id: e.tenant_id.as_uuid().to_string(),
            actor: e.actor.clone(),
            action: domain_audit_action_to_proto(&e.action).into(),
            resource_type: e.resource_type.clone(),
            resource_id: e.resource_id.clone(),
            timestamp: e.timestamp.as_micros(),
            metadata: e.metadata.as_ref().map(ToString::to_string),
            integrity_hash: e.integrity_hash.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AuditEventId, TenantId, Timestamp};

    #[test]
    fn audit_event_to_proto() {
        let event = domain::AuditEvent {
            id: AuditEventId::generate(),
            tenant_id: TenantId::generate(),
            actor: "user_123".to_string(),
            action: domain::AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "user_456".to_string(),
            timestamp: Timestamp::from_micros(1_700_000_000_000_000),
            metadata: Some(serde_json::json!({"ip": "127.0.0.1"})),
            integrity_hash: "abc123".to_string(),
        };

        let proto = pb::AuditEvent::from(&event);
        assert_eq!(proto.id, event.id.as_uuid().to_string());
        assert_eq!(proto.actor, "user_123");
        assert_eq!(proto.action, pb::AuditAction::UserCreated as i32);

        // Verify JSON serialization
        let json: serde_json::Value = serde_json::to_value(&proto).expect("serialize");
        assert_eq!(json["action"], "AUDIT_ACTION_USER_CREATED");
    }

    #[test]
    fn audit_action_all_variants_map() {
        // Ensure every domain variant has a proto mapping
        let variants = [
            domain::AuditAction::UserCreated,
            domain::AuditAction::UserUpdated,
            domain::AuditAction::UserDeleted,
            domain::AuditAction::CredentialSet,
            domain::AuditAction::CredentialChanged,
            domain::AuditAction::CredentialVerified,
            domain::AuditAction::SessionCreated,
            domain::AuditAction::SessionRevoked,
            domain::AuditAction::TokenIssued,
            domain::AuditAction::TokenRefreshed,
            domain::AuditAction::TenantCreated,
            domain::AuditAction::TenantUpdated,
            domain::AuditAction::TenantDeleted,
            domain::AuditAction::ClientRegistered,
            domain::AuditAction::AuthorizationCodeIssued,
            domain::AuditAction::AuthorizationCodeExchanged,
            domain::AuditAction::TupleWritten,
            domain::AuditAction::TupleDeleted,
            domain::AuditAction::ClientUpdated,
            domain::AuditAction::ClientDeleted,
            domain::AuditAction::BulkUsersCreated,
            domain::AuditAction::BulkUsersDisabled,
            domain::AuditAction::OrgCreated,
            domain::AuditAction::OrgUpdated,
            domain::AuditAction::OrgDeleted,
        ];
        for v in &variants {
            let _proto = domain_audit_action_to_proto(v);
        }
    }
}
