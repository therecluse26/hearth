//! Audit event types and query structures.
//!
//! Audit events are append-only structured records of security-critical
//! mutations. Each event includes an integrity hash forming a hash chain
//! for tamper detection.

use crate::core::{AuditEventId, RealmId, Timestamp};
use serde::{Deserialize, Serialize};

/// Categories of security-critical actions recorded in the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuditAction {
    /// A new user was created.
    UserCreated,
    /// A user record was updated.
    UserUpdated,
    /// A user was deleted.
    UserDeleted,
    /// A password was set for a user.
    CredentialSet,
    /// A password was changed.
    CredentialChanged,
    /// A credential verification was attempted (login).
    CredentialVerified,
    /// A new session was created.
    SessionCreated,
    /// A session was revoked.
    SessionRevoked,
    /// Tokens were issued for a session.
    TokenIssued,
    /// Tokens were refreshed.
    TokenRefreshed,
    /// A new realm was created.
    RealmCreated,
    /// A realm record was updated.
    RealmUpdated,
    /// A realm was deleted.
    RealmDeleted,
    /// An OAuth client was registered.
    ClientRegistered,
    /// An authorization code was issued.
    AuthorizationCodeIssued,
    /// An authorization code was exchanged for tokens.
    AuthorizationCodeExchanged,
    /// An authorization tuple was written.
    TupleWritten,
    /// An authorization tuple was deleted.
    TupleDeleted,
    /// An OAuth client was updated via admin API.
    ClientUpdated,
    /// An OAuth client was deleted via admin API.
    ClientDeleted,
    /// Users were bulk-created via admin API.
    BulkUsersCreated,
    /// Users were bulk-disabled via admin API.
    BulkUsersDisabled,
    /// An organization was created.
    OrgCreated,
    /// An organization was updated.
    OrgUpdated,
    /// An organization was deleted.
    OrgDeleted,
    /// A role was assigned to a subject (user) on an object (realm / organization / application).
    ///
    /// Metadata carries `object_type`, `object_id`, `role`, and the previous
    /// role (if any) so downgrades/upgrades are visible in the audit trail.
    RoleAssigned,
    /// A role previously held by a subject was revoked.
    ///
    /// Metadata carries `object_type`, `object_id`, and `role`.
    RoleRevoked,
    /// A user granted OAuth consent to a client for one or more scopes.
    ConsentGranted,
    /// A user denied an OAuth consent request.
    ConsentDenied,
    /// A previously granted OAuth consent was revoked (by the user or an admin).
    ConsentRevoked,
    /// A federation login was initiated (user clicked "Sign in with X").
    FederationLoginStarted,
    /// A federation login completed successfully — either for an
    /// existing user (linked), a JIT-provisioned user, or after a
    /// confirm-to-link step.
    FederationLoginCompleted,
    /// An external identity was attached to a Hearth user.
    FederationAccountLinked,
    /// An external identity was detached from a Hearth user.
    FederationAccountUnlinked,
    /// A fresh Hearth user was JIT-provisioned from a federation login.
    FederationJitProvisioned,
    /// A SAML SP-initiated login was started (AuthnRequest sent).
    SamlLoginInitiated,
    /// A SAML SP-initiated login completed — assertion accepted.
    SamlLoginCompleted,
    /// A SAML assertion was rejected.
    ///
    /// Metadata carries `reason`: `signature` / `expired` / `replay` /
    /// `audience` / `issuer` / `destination` / `parse`.
    SamlLoginFailed,
    /// Hearth (acting as IdP) received a SAML `<AuthnRequest>` from an SP.
    SamlIdpAuthnRequestReceived,
    /// Hearth (acting as IdP) issued a SAML `<Response>` to an SP.
    SamlIdpResponseIssued,
    /// A SAML IdP-initiated SSO was fired (operator launched a login at
    /// a registered SP).
    SamlIdpInitiatedSso,
    /// A SAML Single Logout was requested.
    SamlSloRequested,
    /// A SAML Single Logout completed.
    SamlSloCompleted,
    /// A user was provisioned via the SCIM 2.0 API. Metadata carries
    /// `external_id` (SCIM `externalId`) when supplied by the client.
    ScimUserCreated,
    /// A user was updated (PUT or PATCH) via SCIM.
    ScimUserUpdated,
    /// A user was deprovisioned (DELETE) via SCIM.
    ScimUserDeleted,
    /// A group was provisioned via SCIM.
    ScimGroupCreated,
    /// A group was updated via SCIM.
    ScimGroupUpdated,
    /// A group was deleted via SCIM.
    ScimGroupDeleted,
    /// A dangling role-ID or registry reference was silently skipped
    /// during permission resolution.
    ///
    /// Emitted at most once per `(realm, reference)` per hour so operators
    /// are notified of YAML-storage drift without flooding the audit log.
    /// The `resource_id` field carries the opaque reference (e.g. a
    /// `role_<uuid>` string) that could not be resolved; `metadata` may
    /// carry `ref_kind` for disambiguation. See `AUTHZ_EXPANSION.md`
    /// §"Dangling references".
    OrphanedReferenceSkipped,
}

impl AuditAction {
    /// Returns the string tag for storage key encoding.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserCreated => "user_created",
            Self::UserUpdated => "user_updated",
            Self::UserDeleted => "user_deleted",
            Self::CredentialSet => "credential_set",
            Self::CredentialChanged => "credential_changed",
            Self::CredentialVerified => "credential_verified",
            Self::SessionCreated => "session_created",
            Self::SessionRevoked => "session_revoked",
            Self::TokenIssued => "token_issued",
            Self::TokenRefreshed => "token_refreshed",
            Self::RealmCreated => "realm_created",
            Self::RealmUpdated => "realm_updated",
            Self::RealmDeleted => "realm_deleted",
            Self::ClientRegistered => "client_registered",
            Self::AuthorizationCodeIssued => "authz_code_issued",
            Self::AuthorizationCodeExchanged => "authz_code_exchanged",
            Self::TupleWritten => "tuple_written",
            Self::TupleDeleted => "tuple_deleted",
            Self::ClientUpdated => "client_updated",
            Self::ClientDeleted => "client_deleted",
            Self::BulkUsersCreated => "bulk_users_created",
            Self::BulkUsersDisabled => "bulk_users_disabled",
            Self::OrgCreated => "org_created",
            Self::OrgUpdated => "org_updated",
            Self::OrgDeleted => "org_deleted",
            Self::ConsentGranted => "consent_granted",
            Self::ConsentDenied => "consent_denied",
            Self::ConsentRevoked => "consent_revoked",
            Self::FederationLoginStarted => "federation_login_started",
            Self::FederationLoginCompleted => "federation_login_completed",
            Self::FederationAccountLinked => "federation_account_linked",
            Self::FederationAccountUnlinked => "federation_account_unlinked",
            Self::FederationJitProvisioned => "federation_jit_provisioned",
            Self::SamlLoginInitiated => "saml_login_initiated",
            Self::SamlLoginCompleted => "saml_login_completed",
            Self::SamlLoginFailed => "saml_login_failed",
            Self::SamlIdpAuthnRequestReceived => "saml_idp_authn_request_received",
            Self::SamlIdpResponseIssued => "saml_idp_response_issued",
            Self::SamlIdpInitiatedSso => "saml_idp_initiated_sso",
            Self::SamlSloRequested => "saml_slo_requested",
            Self::SamlSloCompleted => "saml_slo_completed",
            Self::ScimUserCreated => "scim_user_created",
            Self::ScimUserUpdated => "scim_user_updated",
            Self::ScimUserDeleted => "scim_user_deleted",
            Self::ScimGroupCreated => "scim_group_created",
            Self::ScimGroupUpdated => "scim_group_updated",
            Self::ScimGroupDeleted => "scim_group_deleted",
            Self::RoleAssigned => "role_assigned",
            Self::RoleRevoked => "role_revoked",
            Self::OrphanedReferenceSkipped => "orphaned_reference_skipped",
        }
    }
}

impl std::str::FromStr for AuditAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user_created" => Ok(Self::UserCreated),
            "user_updated" => Ok(Self::UserUpdated),
            "user_deleted" => Ok(Self::UserDeleted),
            "credential_set" => Ok(Self::CredentialSet),
            "credential_changed" => Ok(Self::CredentialChanged),
            "credential_verified" => Ok(Self::CredentialVerified),
            "session_created" => Ok(Self::SessionCreated),
            "session_revoked" => Ok(Self::SessionRevoked),
            "token_issued" => Ok(Self::TokenIssued),
            "token_refreshed" => Ok(Self::TokenRefreshed),
            "realm_created" => Ok(Self::RealmCreated),
            "realm_updated" => Ok(Self::RealmUpdated),
            "realm_deleted" => Ok(Self::RealmDeleted),
            "client_registered" => Ok(Self::ClientRegistered),
            "authz_code_issued" => Ok(Self::AuthorizationCodeIssued),
            "authz_code_exchanged" => Ok(Self::AuthorizationCodeExchanged),
            "tuple_written" => Ok(Self::TupleWritten),
            "tuple_deleted" => Ok(Self::TupleDeleted),
            "client_updated" => Ok(Self::ClientUpdated),
            "client_deleted" => Ok(Self::ClientDeleted),
            "bulk_users_created" => Ok(Self::BulkUsersCreated),
            "bulk_users_disabled" => Ok(Self::BulkUsersDisabled),
            "org_created" => Ok(Self::OrgCreated),
            "org_updated" => Ok(Self::OrgUpdated),
            "org_deleted" => Ok(Self::OrgDeleted),
            "consent_granted" => Ok(Self::ConsentGranted),
            "consent_denied" => Ok(Self::ConsentDenied),
            "consent_revoked" => Ok(Self::ConsentRevoked),
            "federation_login_started" => Ok(Self::FederationLoginStarted),
            "federation_login_completed" => Ok(Self::FederationLoginCompleted),
            "federation_account_linked" => Ok(Self::FederationAccountLinked),
            "federation_account_unlinked" => Ok(Self::FederationAccountUnlinked),
            "federation_jit_provisioned" => Ok(Self::FederationJitProvisioned),
            "saml_login_initiated" => Ok(Self::SamlLoginInitiated),
            "saml_login_completed" => Ok(Self::SamlLoginCompleted),
            "saml_login_failed" => Ok(Self::SamlLoginFailed),
            "saml_idp_authn_request_received" => Ok(Self::SamlIdpAuthnRequestReceived),
            "saml_idp_response_issued" => Ok(Self::SamlIdpResponseIssued),
            "saml_idp_initiated_sso" => Ok(Self::SamlIdpInitiatedSso),
            "saml_slo_requested" => Ok(Self::SamlSloRequested),
            "saml_slo_completed" => Ok(Self::SamlSloCompleted),
            "scim_user_created" => Ok(Self::ScimUserCreated),
            "scim_user_updated" => Ok(Self::ScimUserUpdated),
            "scim_user_deleted" => Ok(Self::ScimUserDeleted),
            "scim_group_created" => Ok(Self::ScimGroupCreated),
            "scim_group_updated" => Ok(Self::ScimGroupUpdated),
            "scim_group_deleted" => Ok(Self::ScimGroupDeleted),
            "role_assigned" => Ok(Self::RoleAssigned),
            "role_revoked" => Ok(Self::RoleRevoked),
            "orphaned_reference_skipped" => Ok(Self::OrphanedReferenceSkipped),
            other => Err(format!("unknown audit action: {other}")),
        }
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A recorded audit event in the append-only log.
///
/// Each event forms part of a hash chain for tamper detection.
/// The `integrity_hash` links to the previous event's hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for this event.
    pub id: AuditEventId,
    /// The realm this event belongs to.
    pub realm_id: RealmId,
    /// The actor who performed the action (user ID, "system", etc.).
    pub actor: String,
    /// The type of action performed.
    pub action: AuditAction,
    /// The type of resource affected (e.g., "user", "session", "realm").
    pub resource_type: String,
    /// The identifier of the affected resource.
    pub resource_id: String,
    /// When the event occurred.
    pub timestamp: Timestamp,
    /// Optional additional context (e.g., IP address, user agent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// SHA-256 hash chain link: `SHA256(prev_hash || event_data)`.
    ///
    /// For the first event in a realm's log, `prev_hash` is the
    /// string "genesis".
    pub integrity_hash: String,
}

/// Request to append a new audit event.
///
/// The caller provides the event details; the engine assigns the `id`,
/// `timestamp`, and `integrity_hash`.
#[derive(Clone, Debug)]
pub struct CreateAuditEvent {
    /// The realm this event belongs to.
    pub realm_id: RealmId,
    /// The actor who performed the action.
    pub actor: String,
    /// The type of action performed.
    pub action: AuditAction,
    /// The type of resource affected.
    pub resource_type: String,
    /// The identifier of the affected resource.
    pub resource_id: String,
    /// Optional additional context.
    pub metadata: Option<serde_json::Value>,
}

/// Query parameters for filtering audit events.
///
/// All filters are optional and combined with AND semantics.
/// Results are always returned in chronological order.
#[derive(Clone, Debug)]
pub struct AuditQuery {
    /// Filter by realm (required).
    pub realm_id: RealmId,
    /// Only events at or after this timestamp.
    pub start_time: Option<Timestamp>,
    /// Only events before this timestamp (exclusive).
    pub end_time: Option<Timestamp>,
    /// Only events by this actor.
    pub actor: Option<String>,
    /// Only events of this action type.
    pub action: Option<AuditAction>,
    /// Maximum number of events to return.
    pub limit: Option<usize>,
}

impl AuditQuery {
    /// Creates a new query for a specific realm with no filters.
    pub fn for_realm(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            start_time: None,
            end_time: None,
            actor: None,
            action: None,
            limit: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_action_as_str_round_trips() {
        let actions = [
            AuditAction::UserCreated,
            AuditAction::UserUpdated,
            AuditAction::UserDeleted,
            AuditAction::CredentialSet,
            AuditAction::SessionCreated,
            AuditAction::RealmCreated,
            AuditAction::TupleWritten,
        ];
        for action in &actions {
            let s = action.as_str();
            assert!(!s.is_empty(), "action {action:?} has empty string");
        }
    }

    #[test]
    fn audit_action_display() {
        let action = AuditAction::UserCreated;
        assert_eq!(format!("{action}"), "user_created");
    }

    #[test]
    fn audit_action_serde_round_trip() {
        let action = AuditAction::SessionRevoked;
        let json = serde_json::to_string(&action).expect("serialize");
        let deserialized: AuditAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(action, deserialized);
    }

    #[test]
    fn audit_event_serde_round_trip() {
        let event = AuditEvent {
            id: AuditEventId::generate(),
            realm_id: RealmId::generate(),
            actor: "user_123".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: "user_456".to_string(),
            timestamp: Timestamp::from_micros(1_700_000_000_000_000),
            metadata: Some(serde_json::json!({"ip": "127.0.0.1"})),
            integrity_hash: "abc123".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: AuditEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, deserialized);
    }

    #[test]
    fn create_audit_event_debug() {
        let req = CreateAuditEvent {
            realm_id: RealmId::generate(),
            actor: "system".to_string(),
            action: AuditAction::RealmCreated,
            resource_type: "realm".to_string(),
            resource_id: "realm_789".to_string(),
            metadata: None,
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("RealmCreated"));
    }
}
