//! `AuditService` gRPC implementation.

use tonic::{Request, Response, Status};

use crate::audit::{AuditAction, AuditQuery};
use crate::core::{RealmId, Timestamp};
use crate::protocol::proto::events::v1 as pb;
use crate::protocol::proto::events::v1::audit_service_server::AuditService;

use super::auth::authenticate_admin;
use super::convert::identity_to_status;
use super::server::GrpcState;

/// Implements [`AuditService`] by delegating to the injected [`AuditEngine`].
pub struct AuditSvc {
    state: GrpcState,
}

impl AuditSvc {
    pub fn new(state: GrpcState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl AuditService for AuditSvc {
    async fn list_events(
        &self,
        req: Request<pb::AuditQuery>,
    ) -> Result<Response<pb::AuditEventPage>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let q = req.into_inner();
        let query = proto_query_to_domain(&q, auth.realm_id);
        let events = self
            .state
            .audit
            .query(&query)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(pb::AuditEventPage {
            events: events.iter().map(pb::AuditEvent::from).collect(),
        }))
    }

    async fn verify_integrity(
        &self,
        req: Request<pb::VerifyIntegrityRequest>,
    ) -> Result<Response<pb::VerifyIntegrityResponse>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let ok = self
            .state
            .audit
            .verify_integrity(&auth.realm_id, None, None)
            .map_err(|e| Status::internal(e.to_string()))?;
        // Determine event count for ops visibility.
        let events = self
            .state
            .audit
            .query(&AuditQuery::for_realm(auth.realm_id))
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(pb::VerifyIntegrityResponse {
            ok,
            broken_at_event_id: None,
            event_count: events.len() as u64,
        }))
    }
}

fn proto_query_to_domain(q: &pb::AuditQuery, realm_id: RealmId) -> AuditQuery {
    // `x-realm-id` metadata is authoritative — the body's realm_id is ignored
    // for defence in depth (prevents a caller from querying another realm
    // while authenticated against their own).
    let _ = &q.realm_id;
    AuditQuery {
        realm_id,
        start_time: q.start_time.map(Timestamp::from_micros),
        end_time: q.end_time.map(Timestamp::from_micros),
        actor: q.actor.clone(),
        action: q.action.and_then(|v| proto_action_to_domain(v).ok()),
        limit: q.limit.map(|v| v as usize),
    }
}

fn proto_action_to_domain(v: i32) -> Result<AuditAction, ()> {
    let p = pb::AuditAction::try_from(v).map_err(|_| ())?;
    Ok(match p {
        pb::AuditAction::Unspecified => return Err(()),
        pb::AuditAction::UserCreated => AuditAction::UserCreated,
        pb::AuditAction::UserUpdated => AuditAction::UserUpdated,
        pb::AuditAction::UserDeleted => AuditAction::UserDeleted,
        pb::AuditAction::CredentialSet => AuditAction::CredentialSet,
        pb::AuditAction::CredentialChanged => AuditAction::CredentialChanged,
        pb::AuditAction::CredentialVerified => AuditAction::CredentialVerified,
        pb::AuditAction::SessionCreated => AuditAction::SessionCreated,
        pb::AuditAction::SessionRevoked => AuditAction::SessionRevoked,
        pb::AuditAction::TokenIssued => AuditAction::TokenIssued,
        pb::AuditAction::TokenRefreshed => AuditAction::TokenRefreshed,
        pb::AuditAction::RealmCreated => AuditAction::RealmCreated,
        pb::AuditAction::RealmUpdated => AuditAction::RealmUpdated,
        pb::AuditAction::RealmDeleted => AuditAction::RealmDeleted,
        pb::AuditAction::ClientRegistered => AuditAction::ClientRegistered,
        pb::AuditAction::AuthorizationCodeIssued => AuditAction::AuthorizationCodeIssued,
        pb::AuditAction::AuthorizationCodeExchanged => AuditAction::AuthorizationCodeExchanged,
        pb::AuditAction::TupleWritten => AuditAction::TupleWritten,
        pb::AuditAction::TupleDeleted => AuditAction::TupleDeleted,
        pb::AuditAction::ClientUpdated => AuditAction::ClientUpdated,
        pb::AuditAction::ClientDeleted => AuditAction::ClientDeleted,
        pb::AuditAction::BulkUsersCreated => AuditAction::BulkUsersCreated,
        pb::AuditAction::BulkUsersDisabled => AuditAction::BulkUsersDisabled,
        pb::AuditAction::OrgCreated => AuditAction::OrgCreated,
        pb::AuditAction::OrgUpdated => AuditAction::OrgUpdated,
        pb::AuditAction::OrgDeleted => AuditAction::OrgDeleted,
        pb::AuditAction::ConsentGranted => AuditAction::ConsentGranted,
        pb::AuditAction::ConsentDenied => AuditAction::ConsentDenied,
        pb::AuditAction::ConsentRevoked => AuditAction::ConsentRevoked,
        pb::AuditAction::FederationLoginStarted => AuditAction::FederationLoginStarted,
        pb::AuditAction::FederationLoginCompleted => AuditAction::FederationLoginCompleted,
        pb::AuditAction::FederationAccountLinked => AuditAction::FederationAccountLinked,
        pb::AuditAction::FederationAccountUnlinked => AuditAction::FederationAccountUnlinked,
        pb::AuditAction::FederationJitProvisioned => AuditAction::FederationJitProvisioned,
        pb::AuditAction::SamlLoginInitiated => AuditAction::SamlLoginInitiated,
        pb::AuditAction::SamlLoginCompleted => AuditAction::SamlLoginCompleted,
        pb::AuditAction::SamlLoginFailed => AuditAction::SamlLoginFailed,
        pb::AuditAction::SamlIdpAuthnRequestReceived => AuditAction::SamlIdpAuthnRequestReceived,
        pb::AuditAction::SamlIdpResponseIssued => AuditAction::SamlIdpResponseIssued,
        pb::AuditAction::SamlIdpInitiatedSso => AuditAction::SamlIdpInitiatedSso,
        pb::AuditAction::SamlSloRequested => AuditAction::SamlSloRequested,
        pb::AuditAction::SamlSloCompleted => AuditAction::SamlSloCompleted,
        pb::AuditAction::ScimUserCreated => AuditAction::ScimUserCreated,
        pb::AuditAction::ScimUserUpdated => AuditAction::ScimUserUpdated,
        pb::AuditAction::ScimUserDeleted => AuditAction::ScimUserDeleted,
        pb::AuditAction::ScimGroupCreated => AuditAction::ScimGroupCreated,
        pb::AuditAction::ScimGroupUpdated => AuditAction::ScimGroupUpdated,
        pb::AuditAction::ScimGroupDeleted => AuditAction::ScimGroupDeleted,
        pb::AuditAction::RoleAssigned => AuditAction::RoleAssigned,
        pb::AuditAction::RoleRevoked => AuditAction::RoleRevoked,
    })
}

#[allow(dead_code)]
fn _referenced(err: crate::identity::IdentityError) -> Status {
    // Keep `identity_to_status` imported for potential future use here.
    identity_to_status(err)
}
