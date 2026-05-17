//! Verifies that `seed_realm` failure is promoted to a hard error in the
//! gRPC `create_realm` path (HEA-545).
//!
//! Uses a delegation wrapper (`FailSeedRbac`) that forwards all RBAC calls
//! to the real embedded engine except `seed_realm`, which returns an error.

#![allow(clippy::missing_panics_doc)]

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use hearth::core::{OrganizationId, RealmId, Uri, UserId};
use hearth::identity::{ClientTrustLevel, CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::IdentityAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1::{
    self as pb, identity_admin_service_server::IdentityAdminService,
};
use hearth::rbac::{
    AssignRoleRequest, AssignmentId, CreateGroupRequest, CreateRoleRequest, Group, GroupId,
    GroupMember, GroupMembership, Page, Permission, ProtectedResource, RbacEngine, RbacError,
    ResolvedPermissions, Role, RoleAssignment, RoleId, RoleSpec, RoleSubject, Scope, ScopeSpec,
    Subject, UpdateGroupRequest, UpdateRoleRequest, UserPermissionGrant,
};
use tonic::Request;

/// Forwards all `RbacEngine` calls to `inner` except `seed_realm`, which
/// always returns a storage error. This simulates a transient seed failure
/// at realm-creation time.
struct FailSeedRbac {
    inner: Arc<dyn RbacEngine>,
}

impl RbacEngine for FailSeedRbac {
    fn seed_realm(&self, _realm_id: &RealmId) -> Result<(), RbacError> {
        Err(RbacError::Storage("injected seed failure for test".into()))
    }

    fn resolve_permissions(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
        requested_scope: Option<&str>,
    ) -> Result<ResolvedPermissions, RbacError> {
        self.inner
            .resolve_permissions(user_id, realm_id, org_id, requested_scope)
    }

    fn resolve_with_scopes(
        &self,
        user_id: &UserId,
        realm_id: &RealmId,
        org_id: Option<&OrganizationId>,
        requested_scopes: &[String],
        client_trust_level: ClientTrustLevel,
        declared_scopes: &[String],
        resource: Option<&Uri>,
    ) -> Result<ResolvedPermissions, RbacError> {
        self.inner.resolve_with_scopes(
            user_id,
            realm_id,
            org_id,
            requested_scopes,
            client_trust_level,
            declared_scopes,
            resource,
        )
    }

    fn grant_user_permission(
        &self,
        realm_id: &RealmId,
        grant: &UserPermissionGrant,
    ) -> Result<UserPermissionGrant, RbacError> {
        self.inner.grant_user_permission(realm_id, grant)
    }

    fn revoke_user_permission(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
        permission: &Permission,
        scope: &Scope,
    ) -> Result<(), RbacError> {
        self.inner
            .revoke_user_permission(realm_id, user_id, permission, scope)
    }

    fn list_user_permissions(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<UserPermissionGrant>, RbacError> {
        self.inner.list_user_permissions(realm_id, user_id)
    }

    fn add_additional_role(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role_name: &str,
        granted_by: Option<&UserId>,
    ) -> Result<(), RbacError> {
        self.inner
            .add_additional_role(realm_id, org_id, user_id, role_name, granted_by)
    }

    fn remove_additional_role(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
        role_name: &str,
    ) -> Result<(), RbacError> {
        self.inner
            .remove_additional_role(realm_id, org_id, user_id, role_name)
    }

    fn list_additional_roles(
        &self,
        realm_id: &RealmId,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Vec<String>, RbacError> {
        self.inner.list_additional_roles(realm_id, org_id, user_id)
    }

    fn create_role(&self, realm_id: &RealmId, req: &CreateRoleRequest) -> Result<Role, RbacError> {
        self.inner.create_role(realm_id, req)
    }

    fn get_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<Option<Role>, RbacError> {
        self.inner.get_role(realm_id, role_id)
    }

    fn get_role_by_name(&self, realm_id: &RealmId, name: &str) -> Result<Option<Role>, RbacError> {
        self.inner.get_role_by_name(realm_id, name)
    }

    fn update_role(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
        req: &UpdateRoleRequest,
    ) -> Result<Role, RbacError> {
        self.inner.update_role(realm_id, role_id, req)
    }

    fn delete_role(&self, realm_id: &RealmId, role_id: &RoleId) -> Result<(), RbacError> {
        self.inner.delete_role(realm_id, role_id)
    }

    fn list_roles(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Role>, RbacError> {
        self.inner.list_roles(realm_id, cursor, limit)
    }

    fn create_group(
        &self,
        realm_id: &RealmId,
        req: &CreateGroupRequest,
    ) -> Result<Group, RbacError> {
        self.inner.create_group(realm_id, req)
    }

    fn get_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Option<Group>, RbacError> {
        self.inner.get_group(realm_id, group_id)
    }

    fn update_group(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        req: &UpdateGroupRequest,
    ) -> Result<Group, RbacError> {
        self.inner.update_group(realm_id, group_id, req)
    }

    fn delete_group(&self, realm_id: &RealmId, group_id: &GroupId) -> Result<(), RbacError> {
        self.inner.delete_group(realm_id, group_id)
    }

    fn list_groups(
        &self,
        realm_id: &RealmId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Group>, RbacError> {
        self.inner.list_groups(realm_id, cursor, limit)
    }

    fn add_group_member(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        member: &GroupMember,
    ) -> Result<GroupMembership, RbacError> {
        self.inner.add_group_member(realm_id, group_id, member)
    }

    fn remove_group_member(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        member: &GroupMember,
    ) -> Result<(), RbacError> {
        self.inner.remove_group_member(realm_id, group_id, member)
    }

    fn list_group_members(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<GroupMember>, RbacError> {
        self.inner
            .list_group_members(realm_id, group_id, cursor, limit)
    }

    fn assign_role(
        &self,
        realm_id: &RealmId,
        req: &AssignRoleRequest,
    ) -> Result<RoleAssignment, RbacError> {
        self.inner.assign_role(realm_id, req)
    }

    fn unassign_role(
        &self,
        realm_id: &RealmId,
        assignment_id: &AssignmentId,
    ) -> Result<(), RbacError> {
        self.inner.unassign_role(realm_id, assignment_id)
    }

    fn list_user_assignments(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        self.inner.list_user_assignments(realm_id, user_id)
    }

    fn list_group_assignments(
        &self,
        realm_id: &RealmId,
        group_id: &GroupId,
    ) -> Result<Vec<RoleAssignment>, RbacError> {
        self.inner.list_group_assignments(realm_id, group_id)
    }

    fn list_role_members(
        &self,
        realm_id: &RealmId,
        role_id: &RoleId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<RoleSubject>, RbacError> {
        self.inner
            .list_role_members(realm_id, role_id, cursor, limit)
    }

    fn reconcile_permissions(
        &self,
        realm_id: &RealmId,
        permission_names: &[String],
    ) -> Result<(), RbacError> {
        self.inner.reconcile_permissions(realm_id, permission_names)
    }

    fn reconcile_roles(&self, realm_id: &RealmId, specs: &[RoleSpec]) -> Result<(), RbacError> {
        self.inner.reconcile_roles(realm_id, specs)
    }

    fn reconcile_scopes(&self, realm_id: &RealmId, specs: &[ScopeSpec]) -> Result<(), RbacError> {
        self.inner.reconcile_scopes(realm_id, specs)
    }

    fn reconcile_protected_resources(
        &self,
        realm_id: &RealmId,
        resources: &[ProtectedResource],
    ) -> Result<(), RbacError> {
        self.inner
            .reconcile_protected_resources(realm_id, resources)
    }

    fn reconcile_groups(&self, realm_id: &RealmId, groups: &[Group]) -> Result<(), RbacError> {
        self.inner.reconcile_groups(realm_id, groups)
    }

    fn archive_removed_permissions(
        &self,
        realm_id: &RealmId,
        yaml_names: &HashSet<String>,
    ) -> Result<(), RbacError> {
        self.inner.archive_removed_permissions(realm_id, yaml_names)
    }

    fn archive_removed_roles(
        &self,
        realm_id: &RealmId,
        yaml_names: &HashSet<String>,
    ) -> Result<(), RbacError> {
        self.inner.archive_removed_roles(realm_id, yaml_names)
    }
}

/// `create_realm` must return `Status::INTERNAL` when `seed_realm` fails,
/// not silently swallow the error and leave the realm without RBAC roles.
#[tokio::test]
async fn grpc_create_realm_fails_when_seed_fails() {
    let h = common::TestHarness::embedded().await.expect("harness");

    // Set up an admin user in a fresh realm using the real RBAC engine so
    // we get a valid JWT with hearth.admin embedded in its claims.
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed admin realm");
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("admin-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let admin_role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: admin_role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();

    // Wire the gRPC service with a failing RBAC engine that delegates
    // everything except seed_realm.
    let fail_rbac: Arc<dyn RbacEngine> = Arc::new(FailSeedRbac {
        inner: h.rbac_arc(),
    });
    let svc = IdentityAdminSvc::new(GrpcState::new(
        h.identity_arc(),
        fail_rbac,
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    ));

    let mut req = Request::new(pb::CreateRealmRequest {
        name: format!("fail-seed-{}", uuid::Uuid::new_v4()),
        config: None,
    });
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("meta value"),
    );
    req.metadata_mut().insert(
        "x-realm-id",
        realm.as_uuid().to_string().parse().expect("meta value"),
    );

    let result = svc.create_realm(req).await;
    let status = result.expect_err("create_realm must return an error when seed_realm fails");
    assert_eq!(
        status.code(),
        tonic::Code::Internal,
        "expected Internal status, got: {status:?}"
    );
    assert!(
        status.message().contains("RBAC seed failed"),
        "error message must mention RBAC seed failure, got: {status:?}"
    );
}
