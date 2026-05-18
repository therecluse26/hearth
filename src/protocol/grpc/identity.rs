//! Admin service implementations: users, realms, organizations, applications.

use tonic::{Request, Response, Status};

use crate::core::{ClientId, OrganizationId, UserId};
use crate::identity::{
    self as domain, CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest,
    RegisterClientRequest, UpdateClientRequest, UpdateOrganizationRequest, UpdateRealmRequest,
    UpdateUserRequest,
};
use crate::protocol::convert::identity::{
    domain_realm_status_to_proto, domain_user_status_to_proto, realm_page_to_proto,
    user_page_to_proto,
};
use crate::protocol::convert::oauth::client_page_to_proto;
use crate::protocol::proto::identity::v1 as pb;
use crate::protocol::proto::identity::v1::application_admin_service_server::ApplicationAdminService;
use crate::protocol::proto::identity::v1::identity_admin_service_server::IdentityAdminService;

use super::auth::authenticate_admin;
use super::convert::identity_to_status;
use super::server::GrpcState;

// ==========================================================================
// IdentityAdminService
// ==========================================================================

pub struct IdentityAdminSvc {
    state: GrpcState,
}

impl IdentityAdminSvc {
    pub fn new(state: GrpcState) -> Self {
        Self { state }
    }
}

fn parse_user_id(s: &str) -> Result<UserId, Status> {
    s.parse::<uuid::Uuid>()
        .map(UserId::new)
        .map_err(|_| Status::invalid_argument("invalid user id"))
}

fn parse_realm_id(s: &str) -> Result<crate::core::RealmId, Status> {
    s.parse::<uuid::Uuid>()
        .map(crate::core::RealmId::new)
        .map_err(|_| Status::invalid_argument("invalid realm id"))
}

fn parse_org_id(s: &str) -> Result<OrganizationId, Status> {
    s.parse::<uuid::Uuid>()
        .map(OrganizationId::new)
        .map_err(|_| Status::invalid_argument("invalid organization id"))
}

fn parse_client_id(s: &str) -> Result<ClientId, Status> {
    s.parse::<uuid::Uuid>()
        .map(ClientId::new)
        .map_err(|_| Status::invalid_argument("invalid client id"))
}

fn org_to_proto(o: &domain::Organization) -> pb::Organization {
    pb::Organization {
        id: o.id().as_uuid().to_string(),
        realm_id: String::new(),
        slug: o.slug().to_string(),
        display_name: o.name().to_string(),
        status: match o.status() {
            domain::OrganizationStatus::Active => pb::OrganizationStatus::Active as i32,
            // Archived behaves like Suspended on the wire (no proto value yet).
            domain::OrganizationStatus::Suspended | domain::OrganizationStatus::Archived => {
                pb::OrganizationStatus::Suspended as i32
            }
        },
        created_at: o.created_at().as_micros(),
        updated_at: o.updated_at().as_micros(),
        member_limit: o.config().max_members,
    }
}

fn proto_org_status_to_domain(v: i32) -> Option<domain::OrganizationStatus> {
    match pb::OrganizationStatus::try_from(v).ok()? {
        pb::OrganizationStatus::Unspecified => None,
        pb::OrganizationStatus::Active => Some(domain::OrganizationStatus::Active),
        pb::OrganizationStatus::Suspended => Some(domain::OrganizationStatus::Suspended),
    }
}

#[tonic::async_trait]
impl IdentityAdminService for IdentityAdminSvc {
    // ----- Users -----

    async fn list_users(
        &self,
        req: Request<pb::ListUsersRequest>,
    ) -> Result<Response<pb::UserPage>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let limit = body.limit.unwrap_or(50) as usize;
        let page = self
            .state
            .identity
            .list_users(&auth.realm_id, body.cursor.as_deref(), limit)
            .map_err(identity_to_status)?;
        Ok(Response::new(user_page_to_proto(&page)))
    }

    async fn get_user(
        &self,
        req: Request<pb::GetUserRequest>,
    ) -> Result<Response<pb::User>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let user_id = parse_user_id(&body.id)?;
        let user = self
            .state
            .identity
            .get_user(&auth.realm_id, &user_id)
            .map_err(identity_to_status)?
            .ok_or_else(|| Status::not_found("user not found"))?;
        Ok(Response::new(pb::User::from(&user)))
    }

    async fn create_user(
        &self,
        req: Request<pb::CreateUserRequest>,
    ) -> Result<Response<pb::User>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body: CreateUserRequest = req.into_inner().into();
        let user = self
            .state
            .identity
            .create_user(&auth.realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::User::from(&user)))
    }

    async fn update_user(
        &self,
        req: Request<pb::UpdateUserCall>,
    ) -> Result<Response<pb::User>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let call = req.into_inner();
        let user_id = parse_user_id(&call.id)?;
        let body: UpdateUserRequest = call
            .body
            .ok_or_else(|| Status::invalid_argument("body required"))?
            .into();
        let user = self
            .state
            .identity
            .update_user(&auth.realm_id, &user_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::User::from(&user)))
    }

    async fn delete_user(
        &self,
        req: Request<pb::DeleteUserRequest>,
    ) -> Result<Response<pb::Empty>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let user_id = parse_user_id(&body.id)?;
        self.state
            .identity
            .delete_user(&auth.realm_id, &user_id)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::Empty {}))
    }

    // ----- Realms -----

    async fn list_realms(
        &self,
        req: Request<pb::ListRealmsRequest>,
    ) -> Result<Response<pb::RealmPage>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let limit = body.limit.unwrap_or(50) as usize;
        let page = self
            .state
            .identity
            .list_realms(body.cursor.as_deref(), limit)
            .map_err(identity_to_status)?;
        Ok(Response::new(realm_page_to_proto(&page)))
    }

    async fn get_realm(
        &self,
        req: Request<pb::GetRealmRequest>,
    ) -> Result<Response<pb::Realm>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let realm_id = parse_realm_id(&body.id)?;
        let realm = self
            .state
            .identity
            .get_realm(&realm_id)
            .map_err(identity_to_status)?
            .ok_or_else(|| Status::not_found("realm not found"))?;
        Ok(Response::new(pb::Realm::from(&realm)))
    }

    async fn create_realm(
        &self,
        req: Request<pb::CreateRealmRequest>,
    ) -> Result<Response<pb::Realm>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let body: CreateRealmRequest = req.into_inner().into();
        let realm = self
            .state
            .identity
            .create_realm(&body)
            .map_err(identity_to_status)?;
        // Seed the RBAC defaults on the new realm. Hard error: the caller
        // must see the failure so they can retry or rollback. The realm record
        // is already committed but the unsurfaced-failure path would leave the
        // realm permanently broken with no admin roles.
        self.state
            .rbac
            .seed_realm(realm.id())
            .map_err(|e| Status::internal(format!("RBAC seed failed: {e}")))?;
        Ok(Response::new(pb::Realm::from(&realm)))
    }

    async fn update_realm(
        &self,
        req: Request<pb::UpdateRealmCall>,
    ) -> Result<Response<pb::Realm>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let call = req.into_inner();
        let realm_id = parse_realm_id(&call.id)?;
        let body: UpdateRealmRequest = call
            .body
            .ok_or_else(|| Status::invalid_argument("body required"))?
            .into();
        let realm = self
            .state
            .identity
            .update_realm(&realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::Realm::from(&realm)))
    }

    async fn delete_realm(
        &self,
        req: Request<pb::DeleteRealmRequest>,
    ) -> Result<Response<pb::Empty>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let realm_id = parse_realm_id(&body.id)?;
        self.state
            .identity
            .delete_realm(&realm_id)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::Empty {}))
    }

    // ----- Organizations -----

    async fn list_organizations(
        &self,
        req: Request<pb::ListOrganizationsRequest>,
    ) -> Result<Response<pb::OrganizationPage>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let limit = body.limit.unwrap_or(50) as usize;
        let page = self
            .state
            .identity
            .list_organizations(&auth.realm_id, body.cursor.as_deref(), limit)
            .map_err(identity_to_status)?;
        let items: Vec<_> = page.items.iter().map(org_to_proto).collect();
        Ok(Response::new(pb::OrganizationPage {
            items,
            next_cursor: page.next_cursor,
        }))
    }

    async fn get_organization(
        &self,
        req: Request<pb::GetOrganizationRequest>,
    ) -> Result<Response<pb::Organization>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let org_id = parse_org_id(&body.id)?;
        let org = self
            .state
            .identity
            .get_organization(&auth.realm_id, &org_id)
            .map_err(identity_to_status)?
            .ok_or_else(|| Status::not_found("organization not found"))?;
        Ok(Response::new(org_to_proto(&org)))
    }

    async fn create_organization(
        &self,
        req: Request<pb::CreateOrganizationRequest>,
    ) -> Result<Response<pb::Organization>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let req = CreateOrganizationRequest {
            name: body.display_name,
            slug: body.slug,
            description: None,
            config: body.member_limit.map(|m| domain::OrganizationConfig {
                max_members: Some(m),
            }),
        };
        let org = self
            .state
            .identity
            .create_organization(&auth.realm_id, &req)
            .map_err(identity_to_status)?;
        Ok(Response::new(org_to_proto(&org)))
    }

    async fn update_organization(
        &self,
        req: Request<pb::UpdateOrganizationCall>,
    ) -> Result<Response<pb::Organization>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let call = req.into_inner();
        let org_id = parse_org_id(&call.id)?;
        let body = call
            .body
            .ok_or_else(|| Status::invalid_argument("body required"))?;
        let update = UpdateOrganizationRequest {
            name: body.display_name,
            description: None,
            status: body.status.and_then(proto_org_status_to_domain),
            config: body.member_limit.map(|m| domain::OrganizationConfig {
                max_members: Some(m),
            }),
        };
        let org = self
            .state
            .identity
            .update_organization(&auth.realm_id, &org_id, &update)
            .map_err(identity_to_status)?;
        Ok(Response::new(org_to_proto(&org)))
    }

    async fn delete_organization(
        &self,
        req: Request<pb::DeleteOrganizationRequest>,
    ) -> Result<Response<pb::Empty>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let org_id = parse_org_id(&body.id)?;
        self.state
            .identity
            .delete_organization(&auth.realm_id, &org_id)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::Empty {}))
    }
}

// ==========================================================================
// ApplicationAdminService (OAuth client CRUD)
// ==========================================================================

pub struct AppAdminSvc {
    state: GrpcState,
}

impl AppAdminSvc {
    pub fn new(state: GrpcState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ApplicationAdminService for AppAdminSvc {
    async fn list_applications(
        &self,
        req: Request<pb::ListApplicationsRequest>,
    ) -> Result<Response<pb::OAuthClientPage>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let limit = body.limit.unwrap_or(50) as usize;
        let page = self
            .state
            .identity
            .list_clients(&auth.realm_id, body.cursor.as_deref(), limit)
            .map_err(identity_to_status)?;
        Ok(Response::new(client_page_to_proto(&page)))
    }

    async fn get_application(
        &self,
        req: Request<pb::GetApplicationRequest>,
    ) -> Result<Response<pb::OAuthClient>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let client_id = parse_client_id(&body.client_id)?;
        let client = self
            .state
            .identity
            .get_client(&auth.realm_id, &client_id)
            .map_err(identity_to_status)?
            .ok_or_else(|| Status::not_found("client not found"))?;
        Ok(Response::new(pb::OAuthClient::from(&client)))
    }

    async fn create_application(
        &self,
        req: Request<pb::RegisterClientRequest>,
    ) -> Result<Response<pb::OAuthClient>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body: RegisterClientRequest = req.into_inner().into();
        let client = self
            .state
            .identity
            .register_client(&auth.realm_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OAuthClient::from(&client)))
    }

    async fn update_application(
        &self,
        req: Request<pb::UpdateApplicationCall>,
    ) -> Result<Response<pb::OAuthClient>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let call = req.into_inner();
        let client_id = parse_client_id(&call.client_id)?;
        let body: UpdateClientRequest = call
            .body
            .ok_or_else(|| Status::invalid_argument("body required"))?
            .into();
        let client = self
            .state
            .identity
            .update_client(&auth.realm_id, &client_id, &body)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OAuthClient::from(&client)))
    }

    async fn delete_application(
        &self,
        req: Request<pb::DeleteApplicationRequest>,
    ) -> Result<Response<pb::OAuthEmpty>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let body = req.into_inner();
        let client_id = parse_client_id(&body.client_id)?;
        self.state
            .identity
            .delete_client(&auth.realm_id, &client_id)
            .map_err(identity_to_status)?;
        Ok(Response::new(pb::OAuthEmpty {}))
    }
}

#[allow(dead_code)]
fn _suppress_unused() {
    let _ = domain_user_status_to_proto;
    let _ = domain_realm_status_to_proto;
}
