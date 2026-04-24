//! gRPC implementation of the claims-based RBAC admin service.
//!
//! This module exposes a `tonic` service handler that the top-level gRPC
//! router wires in. Every method requires admin authentication (bearer
//! token + `hearth.admin` permission claim) via [`authenticate_admin`].
//!
//! The handlers are deliberately thin: they parse proto IDs, call into
//! [`RbacEngine`], and map results or errors back to proto + `tonic::Status`.
//! See `docs/specs/AUTHORIZATION.md` § 8.1 for the normative API contract.

use std::sync::Arc;

use tonic::{Code, Request, Response, Status};

use crate::core::{OrganizationId, RealmId, UserId};
use crate::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupId, GroupMember, Permission,
    RbacEngine, RoleId, Scope, Subject, UpdateGroupRequest, UpdateRoleRequest,
};

use super::auth::authenticate_admin;
use super::convert::rbac_to_status;
use super::server::GrpcState;
use crate::protocol::proto::rbac::v1 as pb;
use crate::protocol::proto::rbac::v1::rbac_admin_service_server::RbacAdminService;

/// Concrete `RbacAdminService` implementation backed by [`GrpcState`].
#[derive(Clone)]
pub struct RbacAdminSvc {
    state: Arc<GrpcState>,
}

impl RbacAdminSvc {
    /// Creates a new service from a shared [`GrpcState`].
    pub fn new(state: GrpcState) -> Self {
        Self {
            state: Arc::new(state),
        }
    }
}

// --- helpers ------------------------------------------------------------

fn parse_realm_id(raw: &str) -> Result<RealmId, Status> {
    uuid::Uuid::parse_str(raw)
        .map(RealmId::new)
        .map_err(|_| Status::invalid_argument("invalid realm_id"))
}

fn parse_role_id(raw: &str) -> Result<RoleId, Status> {
    let s = raw.strip_prefix("role_").unwrap_or(raw);
    uuid::Uuid::parse_str(s)
        .map(RoleId::new)
        .map_err(|_| Status::invalid_argument("invalid role_id"))
}

fn parse_group_id(raw: &str) -> Result<GroupId, Status> {
    let s = raw.strip_prefix("group_").unwrap_or(raw);
    uuid::Uuid::parse_str(s)
        .map(GroupId::new)
        .map_err(|_| Status::invalid_argument("invalid group_id"))
}

fn parse_user_id(raw: &str) -> Result<UserId, Status> {
    let s = raw.strip_prefix("user_").unwrap_or(raw);
    uuid::Uuid::parse_str(s)
        .map(UserId::new)
        .map_err(|_| Status::invalid_argument("invalid user_id"))
}

fn parse_assignment_id(raw: &str) -> Result<crate::rbac::AssignmentId, Status> {
    let s = raw.strip_prefix("assign_").unwrap_or(raw);
    uuid::Uuid::parse_str(s)
        .map(crate::rbac::AssignmentId::new)
        .map_err(|_| Status::invalid_argument("invalid assignment_id"))
}

fn permissions_from_strings(raw: &[String]) -> Result<Vec<Permission>, Status> {
    raw.iter()
        .map(|s| {
            Permission::new(s.clone())
                .map_err(|reason| Status::invalid_argument(format!("invalid permission: {reason}")))
        })
        .collect()
}

fn parent_role_ids_from_strings(raw: &[String]) -> Result<Vec<RoleId>, Status> {
    raw.iter().map(|s| parse_role_id(s)).collect()
}

fn effective_limit(limit: u32) -> usize {
    if limit == 0 {
        50
    } else {
        usize::try_from(limit).unwrap_or(50)
    }
}

fn role_to_proto(r: &crate::rbac::Role) -> pb::Role {
    pb::Role {
        id: r.id.to_string(),
        realm_id: r.realm_id.as_uuid().to_string(),
        name: r.name.clone(),
        description: r.description.clone().unwrap_or_default(),
        permissions: r
            .permissions
            .iter()
            .map(|p| p.as_str().to_string())
            .collect(),
        parent_role_ids: r.parent_roles.iter().map(|p| p.to_string()).collect(),
        created_at_micros: r.created_at.as_micros(),
        updated_at_micros: r.updated_at.as_micros(),
    }
}

fn group_to_proto(g: &crate::rbac::Group) -> pb::Group {
    pb::Group {
        id: g.id.to_string(),
        realm_id: g.realm_id.as_uuid().to_string(),
        name: g.name.clone(),
        slug: g.slug.clone(),
        description: g.description.clone().unwrap_or_default(),
        created_at_micros: g.created_at.as_micros(),
        updated_at_micros: g.updated_at.as_micros(),
    }
}

fn group_member_to_proto(m: &GroupMember) -> pb::GroupMember {
    match m {
        GroupMember::User(u) => pb::GroupMember {
            r#type: pb::group_member::Type::User as i32,
            id: u.as_uuid().to_string(),
        },
        GroupMember::Group(g) => pb::GroupMember {
            r#type: pb::group_member::Type::Group as i32,
            id: g.as_uuid().to_string(),
        },
    }
}

fn assignment_to_proto(a: &crate::rbac::RoleAssignment) -> pb::RoleAssignment {
    let (subject_type, subject_id) = match &a.subject {
        Subject::User(u) => (pb::group_member::Type::User as i32, u.as_uuid().to_string()),
        Subject::Group(g) => (
            pb::group_member::Type::Group as i32,
            g.as_uuid().to_string(),
        ),
    };
    let scope = match &a.scope {
        Scope::Realm => pb::Scope {
            kind: Some(pb::scope::Kind::Realm(pb::RealmScope {})),
        },
        Scope::Org { org_id } => pb::Scope {
            kind: Some(pb::scope::Kind::Org(pb::OrgScope {
                org_id: org_id.as_uuid().to_string(),
            })),
        },
    };
    pb::RoleAssignment {
        id: a.id.to_string(),
        realm_id: a.realm_id.as_uuid().to_string(),
        subject_id,
        subject_type,
        role_id: a.role_id.to_string(),
        scope: Some(scope),
        assigned_at_micros: a.assigned_at.as_micros(),
        assigned_by_user_id: a
            .assigned_by
            .as_ref()
            .map(|u| u.as_uuid().to_string())
            .unwrap_or_default(),
    }
}

fn proto_to_group_member(m: &pb::GroupMember) -> Result<GroupMember, Status> {
    let kind = pb::group_member::Type::try_from(m.r#type)
        .map_err(|_| Status::invalid_argument("invalid member type"))?;
    match kind {
        pb::group_member::Type::User => Ok(GroupMember::User(parse_user_id(&m.id)?)),
        pb::group_member::Type::Group => Ok(GroupMember::Group(parse_group_id(&m.id)?)),
        pb::group_member::Type::Unspecified => {
            Err(Status::invalid_argument("member type is unspecified"))
        }
    }
}

fn proto_to_scope(s: Option<&pb::Scope>) -> Result<Scope, Status> {
    let Some(s) = s else {
        return Ok(Scope::Realm);
    };
    match s.kind.as_ref() {
        Some(pb::scope::Kind::Realm(_)) | None => Ok(Scope::Realm),
        Some(pb::scope::Kind::Org(o)) => {
            let stripped = o.org_id.strip_prefix("org_").unwrap_or(o.org_id.as_str());
            let uuid = uuid::Uuid::parse_str(stripped)
                .map_err(|_| Status::invalid_argument("invalid org_id"))?;
            Ok(Scope::Org {
                org_id: OrganizationId::new(uuid),
            })
        }
    }
}

// --- trait impl ---------------------------------------------------------

#[tonic::async_trait]
impl RbacAdminService for RbacAdminSvc {
    async fn list_roles(
        &self,
        req: Request<pb::ListRolesRequest>,
    ) -> Result<Response<pb::ListRolesResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let cursor = if inner.cursor.is_empty() {
            None
        } else {
            Some(inner.cursor.as_str())
        };
        let page = self
            .state
            .rbac
            .list_roles(&realm_id, cursor, effective_limit(inner.limit))
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::ListRolesResponse {
            roles: page.items.iter().map(role_to_proto).collect(),
            next_cursor: page.next_cursor.unwrap_or_default(),
        }))
    }

    async fn create_role(
        &self,
        req: Request<pb::CreateRoleRequest>,
    ) -> Result<Response<pb::Role>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let permissions = permissions_from_strings(&inner.permissions)?;
        let parent_roles = parent_role_ids_from_strings(&inner.parent_role_ids)?;
        let description = if inner.description.is_empty() {
            None
        } else {
            Some(inner.description)
        };
        let role = self
            .state
            .rbac
            .create_role(
                &realm_id,
                &CreateRoleRequest {
                    name: inner.name,
                    description,
                    permissions,
                    parent_roles,
                },
            )
            .map_err(rbac_to_status)?;
        Ok(Response::new(role_to_proto(&role)))
    }

    async fn get_role(
        &self,
        req: Request<pb::GetRoleRequest>,
    ) -> Result<Response<pb::Role>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let role_id = parse_role_id(&inner.role_id)?;
        match self
            .state
            .rbac
            .get_role(&realm_id, &role_id)
            .map_err(rbac_to_status)?
        {
            Some(r) => Ok(Response::new(role_to_proto(&r))),
            None => Err(Status::new(Code::NotFound, "role not found")),
        }
    }

    async fn update_role(
        &self,
        req: Request<pb::UpdateRoleRequest>,
    ) -> Result<Response<pb::Role>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let role_id = parse_role_id(&inner.role_id)?;
        // The proto uses "empty string = unchanged" semantics for name/description
        // and "always replace" semantics for permissions/parent_role_ids.
        let name = if inner.name.is_empty() {
            None
        } else {
            Some(inner.name)
        };
        let description = if inner.description.is_empty() {
            None
        } else {
            Some(Some(inner.description))
        };
        let permissions = Some(permissions_from_strings(&inner.permissions)?);
        let parent_roles = Some(parent_role_ids_from_strings(&inner.parent_role_ids)?);
        let updated = self
            .state
            .rbac
            .update_role(
                &realm_id,
                &role_id,
                &UpdateRoleRequest {
                    name,
                    description,
                    permissions,
                    parent_roles,
                },
            )
            .map_err(rbac_to_status)?;
        Ok(Response::new(role_to_proto(&updated)))
    }

    async fn delete_role(
        &self,
        req: Request<pb::DeleteRoleRequest>,
    ) -> Result<Response<pb::DeleteRoleResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let role_id = parse_role_id(&inner.role_id)?;
        self.state
            .rbac
            .delete_role(&realm_id, &role_id)
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::DeleteRoleResponse {}))
    }

    async fn list_groups(
        &self,
        req: Request<pb::ListGroupsRequest>,
    ) -> Result<Response<pb::ListGroupsResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let cursor = if inner.cursor.is_empty() {
            None
        } else {
            Some(inner.cursor.as_str())
        };
        let page = self
            .state
            .rbac
            .list_groups(&realm_id, cursor, effective_limit(inner.limit))
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::ListGroupsResponse {
            groups: page.items.iter().map(group_to_proto).collect(),
            next_cursor: page.next_cursor.unwrap_or_default(),
        }))
    }

    async fn create_group(
        &self,
        req: Request<pb::CreateGroupRequest>,
    ) -> Result<Response<pb::Group>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let description = if inner.description.is_empty() {
            None
        } else {
            Some(inner.description)
        };
        let g = self
            .state
            .rbac
            .create_group(
                &realm_id,
                &CreateGroupRequest {
                    name: inner.name,
                    slug: inner.slug,
                    description,
                },
            )
            .map_err(rbac_to_status)?;
        Ok(Response::new(group_to_proto(&g)))
    }

    async fn get_group(
        &self,
        req: Request<pb::GetGroupRequest>,
    ) -> Result<Response<pb::Group>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let group_id = parse_group_id(&inner.group_id)?;
        match self
            .state
            .rbac
            .get_group(&realm_id, &group_id)
            .map_err(rbac_to_status)?
        {
            Some(g) => Ok(Response::new(group_to_proto(&g))),
            None => Err(Status::new(Code::NotFound, "group not found")),
        }
    }

    async fn update_group(
        &self,
        req: Request<pb::UpdateGroupRequest>,
    ) -> Result<Response<pb::Group>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let group_id = parse_group_id(&inner.group_id)?;
        let name = if inner.name.is_empty() {
            None
        } else {
            Some(inner.name)
        };
        let slug = if inner.slug.is_empty() {
            None
        } else {
            Some(inner.slug)
        };
        let description = if inner.description.is_empty() {
            None
        } else {
            Some(Some(inner.description))
        };
        let g = self
            .state
            .rbac
            .update_group(
                &realm_id,
                &group_id,
                &UpdateGroupRequest {
                    name,
                    slug,
                    description,
                },
            )
            .map_err(rbac_to_status)?;
        Ok(Response::new(group_to_proto(&g)))
    }

    async fn delete_group(
        &self,
        req: Request<pb::DeleteGroupRequest>,
    ) -> Result<Response<pb::DeleteGroupResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let group_id = parse_group_id(&inner.group_id)?;
        self.state
            .rbac
            .delete_group(&realm_id, &group_id)
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::DeleteGroupResponse {}))
    }

    async fn list_group_members(
        &self,
        req: Request<pb::ListGroupMembersRequest>,
    ) -> Result<Response<pb::ListGroupMembersResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let group_id = parse_group_id(&inner.group_id)?;
        let cursor = if inner.cursor.is_empty() {
            None
        } else {
            Some(inner.cursor.as_str())
        };
        let page = self
            .state
            .rbac
            .list_group_members(&realm_id, &group_id, cursor, effective_limit(inner.limit))
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::ListGroupMembersResponse {
            members: page.items.iter().map(group_member_to_proto).collect(),
            next_cursor: page.next_cursor.unwrap_or_default(),
        }))
    }

    async fn add_group_member(
        &self,
        req: Request<pb::AddGroupMemberRequest>,
    ) -> Result<Response<pb::GroupMembership>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let group_id = parse_group_id(&inner.group_id)?;
        let member_proto = inner
            .member
            .ok_or_else(|| Status::invalid_argument("missing member"))?;
        let member = proto_to_group_member(&member_proto)?;
        let mem = self
            .state
            .rbac
            .add_group_member(&realm_id, &group_id, &member)
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::GroupMembership {
            group_id: mem.group_id.to_string(),
            member: Some(group_member_to_proto(&mem.member)),
            added_at_micros: mem.added_at.as_micros(),
            added_by_user_id: mem
                .added_by
                .as_ref()
                .map(|u| u.as_uuid().to_string())
                .unwrap_or_default(),
        }))
    }

    async fn remove_group_member(
        &self,
        req: Request<pb::RemoveGroupMemberRequest>,
    ) -> Result<Response<pb::RemoveGroupMemberResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let group_id = parse_group_id(&inner.group_id)?;
        let member_proto = inner
            .member
            .ok_or_else(|| Status::invalid_argument("missing member"))?;
        let member = proto_to_group_member(&member_proto)?;
        self.state
            .rbac
            .remove_group_member(&realm_id, &group_id, &member)
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::RemoveGroupMemberResponse {}))
    }

    async fn assign_user_role(
        &self,
        req: Request<pb::AssignUserRoleRequest>,
    ) -> Result<Response<pb::RoleAssignment>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let user_id = parse_user_id(&inner.user_id)?;
        let role_id = parse_role_id(&inner.role_id)?;
        let scope = proto_to_scope(inner.scope.as_ref())?;
        let assignment = self
            .state
            .rbac
            .assign_role(
                &realm_id,
                &AssignRoleRequest {
                    subject: Subject::User(user_id),
                    role_id,
                    scope,
                    assigned_by: None,
                },
            )
            .map_err(rbac_to_status)?;
        Ok(Response::new(assignment_to_proto(&assignment)))
    }

    async fn unassign_user_role(
        &self,
        req: Request<pb::UnassignUserRoleRequest>,
    ) -> Result<Response<pb::UnassignUserRoleResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let aid = parse_assignment_id(&inner.assignment_id)?;
        self.state
            .rbac
            .unassign_role(&realm_id, &aid)
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::UnassignUserRoleResponse {}))
    }

    async fn list_user_assignments(
        &self,
        req: Request<pb::ListUserAssignmentsRequest>,
    ) -> Result<Response<pb::ListUserAssignmentsResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let user_id = parse_user_id(&inner.user_id)?;
        let assignments = self
            .state
            .rbac
            .list_user_assignments(&realm_id, &user_id)
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::ListUserAssignmentsResponse {
            assignments: assignments.iter().map(assignment_to_proto).collect(),
        }))
    }

    async fn assign_group_role(
        &self,
        req: Request<pb::AssignGroupRoleRequest>,
    ) -> Result<Response<pb::RoleAssignment>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let group_id = parse_group_id(&inner.group_id)?;
        let role_id = parse_role_id(&inner.role_id)?;
        let scope = proto_to_scope(inner.scope.as_ref())?;
        let assignment = self
            .state
            .rbac
            .assign_role(
                &realm_id,
                &AssignRoleRequest {
                    subject: Subject::Group(group_id),
                    role_id,
                    scope,
                    assigned_by: None,
                },
            )
            .map_err(rbac_to_status)?;
        Ok(Response::new(assignment_to_proto(&assignment)))
    }

    async fn unassign_group_role(
        &self,
        req: Request<pb::UnassignGroupRoleRequest>,
    ) -> Result<Response<pb::UnassignGroupRoleResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let aid = parse_assignment_id(&inner.assignment_id)?;
        self.state
            .rbac
            .unassign_role(&realm_id, &aid)
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::UnassignGroupRoleResponse {}))
    }

    async fn list_role_members(
        &self,
        req: Request<pb::ListRoleMembersRequest>,
    ) -> Result<Response<pb::ListRoleMembersResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let role_id = parse_role_id(&inner.role_id)?;
        let cursor = if inner.cursor.is_empty() {
            None
        } else {
            Some(inner.cursor.as_str())
        };
        let page = self
            .state
            .rbac
            .list_role_members(&realm_id, &role_id, cursor, effective_limit(inner.limit))
            .map_err(rbac_to_status)?;
        let members: Vec<pb::RoleSubject> = page
            .items
            .iter()
            .map(|s| match s {
                crate::rbac::RoleSubject::User(u) => pb::RoleSubject {
                    subject_type: pb::group_member::Type::User as i32,
                    subject_id: u.as_uuid().to_string(),
                },
                crate::rbac::RoleSubject::Group(g) => pb::RoleSubject {
                    subject_type: pb::group_member::Type::Group as i32,
                    subject_id: g.as_uuid().to_string(),
                },
            })
            .collect();
        Ok(Response::new(pb::ListRoleMembersResponse {
            members,
            next_cursor: page.next_cursor.unwrap_or_default(),
        }))
    }

    async fn resolve_effective_permissions(
        &self,
        req: Request<pb::ResolveEffectivePermissionsRequest>,
    ) -> Result<Response<pb::ResolveEffectivePermissionsResponse>, Status> {
        let _auth = authenticate_admin(req.metadata(), &self.state)?;
        let inner = req.into_inner();
        let realm_id = parse_realm_id(&inner.realm_id)?;
        let user_id = parse_user_id(&inner.user_id)?;
        let org_id = if inner.org_id.is_empty() {
            None
        } else {
            let s = inner
                .org_id
                .strip_prefix("org_")
                .unwrap_or(inner.org_id.as_str());
            Some(
                uuid::Uuid::parse_str(s)
                    .map(OrganizationId::new)
                    .map_err(|_| Status::invalid_argument("invalid org_id"))?,
            )
        };
        let scope = if inner.scope.is_empty() {
            None
        } else {
            Some(inner.scope.as_str())
        };
        let resolved = self
            .state
            .rbac
            .resolve_permissions(&user_id, &realm_id, org_id.as_ref(), scope)
            .map_err(rbac_to_status)?;
        Ok(Response::new(pb::ResolveEffectivePermissionsResponse {
            roles: resolved.roles,
            groups: resolved.groups,
            permissions: resolved
                .permissions
                .into_iter()
                .map(|p| p.into_string())
                .collect(),
        }))
    }
}
