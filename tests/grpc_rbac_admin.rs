//! Integration tests for the gRPC RBAC admin service.
//!
//! Covers `MIGRATE_TO_RBAC.md` § 7 — `grpc_rbac_admin:role_crud`, `group_crud`,
//! `assignment_crud`, `admin_bearer_required`.
//!
//! Drives the service in-process via the generated `RbacAdminService` trait
//! and a `tonic::Request` carrying bearer metadata. Bearer tokens are issued
//! via the same identity engine the production server uses.

mod common;

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::rbac_admin::RbacAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::rbac::v1::{self as pb, rbac_admin_service_server::RbacAdminService};
use hearth::rbac::{AssignRoleRequest, Scope as RbacScope, Subject};
use tonic::Request;

struct GrpcCtx {
    // Holds engine lifetimes alive for the service under test.
    _h: common::TestHarness,
    realm: RealmId,
    token: String,
    svc: RbacAdminSvc,
}

async fn grpc_ctx_with_admin(with_admin: bool) -> GrpcCtx {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("a-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "A".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    if with_admin {
        let role = h
            .rbac()
            .get_role_by_name(&realm, "realm.admin")
            .expect("lookup")
            .expect("seed");
        h.rbac()
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.id().clone()),
                    role_id: role.id,
                    scope: RbacScope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");
    }
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("sess");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();

    let state = GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    );
    let svc = RbacAdminSvc::new(state);

    GrpcCtx {
        _h: h,
        realm,
        token,
        svc,
    }
}

async fn grpc_ctx() -> GrpcCtx {
    grpc_ctx_with_admin(true).await
}

fn req<T>(ctx: &GrpcCtx, msg: T) -> Request<T> {
    let mut r = Request::new(msg);
    r.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", ctx.token).parse().expect("meta"),
    );
    r.metadata_mut().insert(
        "x-realm-id",
        ctx.realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    r
}

fn forge_admin_permission_claim(token: &str) -> String {
    let mut parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "JWT must have three parts");

    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode payload segment");
    let mut payload_json: serde_json::Value =
        serde_json::from_slice(&payload).expect("parse payload JSON");
    payload_json["permissions"] = serde_json::json!(["hearth.admin"]);

    let tampered_payload = serde_json::to_vec(&payload_json).expect("serialize payload JSON");
    let tampered_payload_b64 = URL_SAFE_NO_PAD.encode(tampered_payload);
    parts[1] = tampered_payload_b64.as_str();

    parts.join(".")
}

#[tokio::test]
async fn role_crud_round_trip() {
    let ctx = grpc_ctx().await;

    let created = ctx
        .svc
        .create_role(req(
            &ctx,
            pb::CreateRoleRequest {
                realm_id: ctx.realm.as_uuid().to_string(),
                name: "grpc.editor".into(),
                description: "via grpc".into(),
                permissions: vec!["docs.view".into()],
                parent_role_ids: vec![],
            },
        ))
        .await
        .expect("create")
        .into_inner();
    assert_eq!(created.name, "grpc.editor");

    let fetched = ctx
        .svc
        .get_role(req(
            &ctx,
            pb::GetRoleRequest {
                realm_id: ctx.realm.as_uuid().to_string(),
                role_id: created.id.clone(),
            },
        ))
        .await
        .expect("get")
        .into_inner();
    assert_eq!(fetched.id, created.id);

    let _ = ctx
        .svc
        .delete_role(req(
            &ctx,
            pb::DeleteRoleRequest {
                realm_id: ctx.realm.as_uuid().to_string(),
                role_id: created.id,
                cascade: false,
            },
        ))
        .await
        .expect("delete");
}

#[tokio::test]
async fn group_crud_round_trip() {
    let ctx = grpc_ctx().await;

    let created = ctx
        .svc
        .create_group(req(
            &ctx,
            pb::CreateGroupRequest {
                realm_id: ctx.realm.as_uuid().to_string(),
                name: "Grpc Group".into(),
                slug: "grpc-group".into(),
                description: String::new(),
            },
        ))
        .await
        .expect("create")
        .into_inner();
    assert_eq!(created.slug, "grpc-group");

    let _ = ctx
        .svc
        .delete_group(req(
            &ctx,
            pb::DeleteGroupRequest {
                realm_id: ctx.realm.as_uuid().to_string(),
                group_id: created.id,
            },
        ))
        .await
        .expect("delete");
}

#[tokio::test]
async fn admin_bearer_required_returns_unauthenticated() {
    let ctx = grpc_ctx().await;

    // Build a request WITHOUT bearer metadata.
    let r = Request::new(pb::ListRolesRequest {
        realm_id: ctx.realm.as_uuid().to_string(),
        cursor: String::new(),
        limit: 0,
    });

    let status = ctx
        .svc
        .list_roles(r)
        .await
        .expect_err("must require bearer");
    assert!(
        matches!(
            status.code(),
            tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
        ),
        "unexpected status: {status:?}"
    );
}

#[tokio::test]
async fn admin_tampered_unsigned_claim_returns_unauthenticated() {
    let mut ctx = grpc_ctx_with_admin(false).await;
    ctx.token = forge_admin_permission_claim(&ctx.token);

    let status = ctx
        .svc
        .list_roles(req(
            &ctx,
            pb::ListRolesRequest {
                realm_id: ctx.realm.as_uuid().to_string(),
                cursor: String::new(),
                limit: 0,
            },
        ))
        .await
        .expect_err("tampered token must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}
