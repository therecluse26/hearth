//! gRPC transport: shared state, router construction, serve entry point.
//!
//! Mirrors the HTTP `serve_router` pattern from `src/protocol/http.rs` but
//! binds a `tonic::transport::Server` instead of an Axum listener. Admin
//! services share the [`AdminRateLimiter`] with the REST surface so a
//! caller cannot evade the 100 req/min budget by switching protocols.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tracing::{debug, info};

use crate::audit::AuditEngine;
use crate::authz::AuthorizationEngine;
use crate::identity::IdentityEngine;
use crate::protocol::admin_auth::AdminRateLimiter;

use super::audit::AuditSvc;
use super::authz::AuthzSvc;
use super::identity::{AppAdminSvc, IdentityAdminSvc};
use super::oauth::OAuthSvc;

/// Shared state for all gRPC services.
///
/// Built once at startup and cloned (Arc) into each service handler.
#[derive(Clone)]
pub struct GrpcState {
    pub identity: Arc<dyn IdentityEngine>,
    pub authz: Arc<dyn AuthorizationEngine>,
    pub audit: Arc<dyn AuditEngine>,
    pub admin_rate_limiter: Arc<AdminRateLimiter>,
}

impl GrpcState {
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        authz: Arc<dyn AuthorizationEngine>,
        audit: Arc<dyn AuditEngine>,
        admin_rate_limiter: Arc<AdminRateLimiter>,
    ) -> Self {
        Self {
            identity,
            authz,
            audit,
            admin_rate_limiter,
        }
    }
}

/// Max decoded message size (1 MiB), matches the HTTP `BODY_LIMIT_DEFAULT`.
const MAX_DECODING_MESSAGE_SIZE: usize = 1024 * 1024;

/// Builds a fully-wired `tonic::transport::Server::router()` ready to serve.
///
/// Includes all Hearth services plus `grpc.health.v1.Health` (reports SERVING
/// by default) and `grpc.reflection.v1.ServerReflection` for grpcurl / Postman.
pub async fn build_router(
    state: GrpcState,
) -> Result<tonic::transport::server::Router, Box<dyn std::error::Error + Send + Sync>> {
    use crate::protocol::proto::authz::v1::authorization_service_server::AuthorizationServiceServer;
    use crate::protocol::proto::events::v1::audit_service_server::AuditServiceServer;
    use crate::protocol::proto::identity::v1::application_admin_service_server::ApplicationAdminServiceServer;
    use crate::protocol::proto::identity::v1::identity_admin_service_server::IdentityAdminServiceServer;
    use crate::protocol::proto::identity::v1::o_auth_service_server::OAuthServiceServer;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    // Mark every Hearth service SERVING by default; graceful shutdown will
    // flip them to NOT_SERVING before the listener closes.
    health_reporter
        .set_serving::<IdentityAdminServiceServer<IdentityAdminSvc>>()
        .await;
    health_reporter
        .set_serving::<ApplicationAdminServiceServer<AppAdminSvc>>()
        .await;
    health_reporter
        .set_serving::<AuthorizationServiceServer<AuthzSvc>>()
        .await;
    health_reporter
        .set_serving::<AuditServiceServer<AuditSvc>>()
        .await;
    health_reporter
        .set_serving::<OAuthServiceServer<OAuthSvc>>()
        .await;

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(super::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    let identity_svc = IdentityAdminServiceServer::new(IdentityAdminSvc::new(state.clone()))
        .max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE);
    let app_svc = ApplicationAdminServiceServer::new(AppAdminSvc::new(state.clone()))
        .max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE);
    let authz_svc = AuthorizationServiceServer::new(AuthzSvc::new(state.clone()))
        .max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE);
    let audit_svc = AuditServiceServer::new(AuditSvc::new(state.clone()))
        .max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE);
    let oauth_svc = OAuthServiceServer::new(OAuthSvc::new(state))
        .max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE);

    let router = Server::builder()
        .timeout(Duration::from_secs(60))
        .add_service(health_service)
        .add_service(reflection)
        .add_service(identity_svc)
        .add_service(app_svc)
        .add_service(authz_svc)
        .add_service(audit_svc)
        .add_service(oauth_svc);

    Ok(router)
}

/// Binds a listener on `addr` and serves gRPC until `shutdown` resolves.
pub async fn serve<F>(
    addr: SocketAddr,
    state: GrpcState,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    info!(address = %local, "gRPC listener bound");
    let incoming = TcpListenerStream::new(listener);
    let router = build_router(state).await?;
    router
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await?;
    debug!("gRPC server stopped");
    Ok(())
}
