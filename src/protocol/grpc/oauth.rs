//! `OAuthService` gRPC implementation.
//!
//! The OAuth surface authenticates via per-RPC client credentials (not the
//! admin bearer interceptor). The target realm is supplied via the
//! `x-realm-id` metadata header, same as the admin surface — gRPC clients
//! typically have dedicated per-realm stubs so this is not a usability
//! burden.

use tonic::{Request, Response, Status};

use crate::core::ClientId;
use crate::identity::{self as domain, DeviceAuthorizationRequest};
use crate::protocol::convert::oauth::{
    proto_authorize_to_domain, proto_client_creds_to_domain, proto_token_exchange_to_domain,
};
use crate::protocol::proto::identity::v1 as pb;
use crate::protocol::proto::identity::v1::o_auth_service_server::OAuthService;

use super::convert::{extract_realm_id, identity_to_status, verify_grpc_client_auth};
use super::server::GrpcState;

pub struct OAuthSvc {
    state: GrpcState,
}

impl OAuthSvc {
    pub fn new(state: GrpcState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl OAuthService for OAuthSvc {
    async fn authorize(
        &self,
        req: Request<pb::AuthorizationRequest>,
    ) -> Result<Response<pb::AuthorizationResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body = req.into_inner();
        let domain_req = proto_authorize_to_domain(body).map_err(Status::invalid_argument)?;
        let resp = self
            .state
            .identity
            .authorize(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::AuthorizationResponse::from(&resp)))
    }

    async fn token_exchange(
        &self,
        req: Request<pb::TokenExchangeRequest>,
    ) -> Result<Response<pb::OidcTokenResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body = req.into_inner();
        let domain_req = proto_token_exchange_to_domain(&body).map_err(Status::invalid_argument)?;
        let resp = self
            .state
            .identity
            .exchange_authorization_code(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OidcTokenResponse::from(&resp)))
    }

    async fn revoke(
        &self,
        req: Request<pb::TokenRevocationRequest>,
    ) -> Result<Response<pb::OAuthEmpty>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        verify_grpc_client_auth(req.metadata(), &realm_id, self.state.identity.as_ref())?;
        let body: domain::TokenRevocationRequest = req.into_inner().into();
        self.state
            .identity
            .revoke_token(&realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OAuthEmpty {}))
    }

    async fn introspect(
        &self,
        req: Request<pb::TokenIntrospectionRequest>,
    ) -> Result<Response<pb::IntrospectionResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        verify_grpc_client_auth(req.metadata(), &realm_id, self.state.identity.as_ref())?;
        let body: domain::TokenIntrospectionRequest = req.into_inner().into();
        let resp = self
            .state
            .identity
            .introspect_token(&realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::IntrospectionResponse::from(&resp)))
    }

    async fn device_authorize(
        &self,
        req: Request<pb::DeviceAuthorizationRequest>,
    ) -> Result<Response<pb::DeviceAuthorizationResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body = req.into_inner();
        let client_id = body
            .client_id
            .parse::<uuid::Uuid>()
            .map(ClientId::new)
            .map_err(|_| Status::invalid_argument("invalid client_id UUID"))?;
        let domain_req = DeviceAuthorizationRequest {
            client_id,
            scope: body.scope,
        };
        let resp = self
            .state
            .identity
            .device_authorize(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::DeviceAuthorizationResponse::from(&resp)))
    }

    async fn client_credentials(
        &self,
        req: Request<pb::ClientCredentialsRequest>,
    ) -> Result<Response<pb::ClientCredentialsResponse>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body = req.into_inner();
        let domain_req = proto_client_creds_to_domain(&body).map_err(Status::invalid_argument)?;
        let resp = self
            .state
            .identity
            .client_credentials_token(&realm_id, &domain_req)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::ClientCredentialsResponse::from(&resp)))
    }

    async fn register_client(
        &self,
        req: Request<pb::RegisterClientRequest>,
    ) -> Result<Response<pb::OAuthClient>, Status> {
        let realm_id = extract_realm_id(req.metadata())?;
        let body: domain::RegisterClientRequest = req.into_inner().into();
        let client = self
            .state
            .identity
            .register_client(&realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OAuthClient::from(&client)))
    }
}
