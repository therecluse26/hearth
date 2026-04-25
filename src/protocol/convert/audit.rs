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
        domain::AuditAction::RealmCreated => pb::AuditAction::RealmCreated,
        domain::AuditAction::RealmUpdated => pb::AuditAction::RealmUpdated,
        domain::AuditAction::RealmDeleted => pb::AuditAction::RealmDeleted,
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
        domain::AuditAction::ConsentGranted => pb::AuditAction::ConsentGranted,
        domain::AuditAction::ConsentDenied => pb::AuditAction::ConsentDenied,
        domain::AuditAction::ConsentRevoked => pb::AuditAction::ConsentRevoked,
        domain::AuditAction::FederationLoginStarted => pb::AuditAction::FederationLoginStarted,
        domain::AuditAction::FederationLoginCompleted => pb::AuditAction::FederationLoginCompleted,
        domain::AuditAction::FederationAccountLinked => pb::AuditAction::FederationAccountLinked,
        domain::AuditAction::FederationAccountUnlinked => {
            pb::AuditAction::FederationAccountUnlinked
        }
        domain::AuditAction::FederationJitProvisioned => pb::AuditAction::FederationJitProvisioned,
        domain::AuditAction::SamlLoginInitiated => pb::AuditAction::SamlLoginInitiated,
        domain::AuditAction::SamlLoginCompleted => pb::AuditAction::SamlLoginCompleted,
        domain::AuditAction::SamlLoginFailed => pb::AuditAction::SamlLoginFailed,
        domain::AuditAction::SamlIdpAuthnRequestReceived => {
            pb::AuditAction::SamlIdpAuthnRequestReceived
        }
        domain::AuditAction::SamlIdpResponseIssued => pb::AuditAction::SamlIdpResponseIssued,
        domain::AuditAction::SamlIdpInitiatedSso => pb::AuditAction::SamlIdpInitiatedSso,
        domain::AuditAction::SamlSloRequested => pb::AuditAction::SamlSloRequested,
        domain::AuditAction::SamlSloCompleted => pb::AuditAction::SamlSloCompleted,
        domain::AuditAction::ScimUserCreated => pb::AuditAction::ScimUserCreated,
        domain::AuditAction::ScimUserUpdated => pb::AuditAction::ScimUserUpdated,
        domain::AuditAction::ScimUserDeleted => pb::AuditAction::ScimUserDeleted,
        domain::AuditAction::ScimGroupCreated => pb::AuditAction::ScimGroupCreated,
        domain::AuditAction::ScimGroupUpdated => pb::AuditAction::ScimGroupUpdated,
        domain::AuditAction::ScimGroupDeleted => pb::AuditAction::ScimGroupDeleted,
        domain::AuditAction::RoleAssigned => pb::AuditAction::RoleAssigned,
        domain::AuditAction::RoleRevoked => pb::AuditAction::RoleRevoked,
        // OrphanedReferenceSkipped has no proto variant yet (gap #7 — proto
        // RPC work is deferred). Serialize as Unspecified so existing gRPC
        // clients see it as an unknown action rather than crashing.
        domain::AuditAction::OrphanedReferenceSkipped => pb::AuditAction::Unspecified,
    }
}

// ==================== AuditEvent ====================

impl From<&domain::AuditEvent> for pb::AuditEvent {
    fn from(e: &domain::AuditEvent) -> Self {
        Self {
            id: e.id.as_uuid().to_string(),
            realm_id: e.realm_id.as_uuid().to_string(),
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
    use crate::core::{AuditEventId, RealmId, Timestamp};

    #[test]
    fn audit_event_to_proto() {
        let event = domain::AuditEvent {
            id: AuditEventId::generate(),
            realm_id: RealmId::generate(),
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
            domain::AuditAction::RealmCreated,
            domain::AuditAction::RealmUpdated,
            domain::AuditAction::RealmDeleted,
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
            domain::AuditAction::ConsentGranted,
            domain::AuditAction::ConsentDenied,
            domain::AuditAction::ConsentRevoked,
            domain::AuditAction::FederationLoginStarted,
            domain::AuditAction::FederationLoginCompleted,
            domain::AuditAction::FederationAccountLinked,
            domain::AuditAction::FederationAccountUnlinked,
            domain::AuditAction::FederationJitProvisioned,
            domain::AuditAction::SamlLoginInitiated,
            domain::AuditAction::SamlLoginCompleted,
            domain::AuditAction::SamlLoginFailed,
            domain::AuditAction::SamlIdpAuthnRequestReceived,
            domain::AuditAction::SamlIdpResponseIssued,
            domain::AuditAction::SamlIdpInitiatedSso,
            domain::AuditAction::SamlSloRequested,
            domain::AuditAction::SamlSloCompleted,
            domain::AuditAction::ScimUserCreated,
            domain::AuditAction::ScimUserUpdated,
            domain::AuditAction::ScimUserDeleted,
            domain::AuditAction::ScimGroupCreated,
            domain::AuditAction::ScimGroupUpdated,
            domain::AuditAction::ScimGroupDeleted,
            domain::AuditAction::RoleAssigned,
            domain::AuditAction::RoleRevoked,
            domain::AuditAction::OrphanedReferenceSkipped,
        ];
        for v in &variants {
            let _proto = domain_audit_action_to_proto(v);
        }
    }
}
