//! HTTP server and route definitions.
//!
//! Builds an [`axum::Router`] with health, OIDC discovery, JWKS, OAuth 2.0,
//! and Admin API endpoints. The server is configured with shared application
//! state containing the identity, RBAC, and audit engines.
//!
//! The protocol layer is a thin, stateless adapter: it translates HTTP requests
//! into domain calls on `IdentityEngine` and maps `IdentityError` to HTTP
//! status codes. No business logic lives here.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::audit::{AuditEngine, CreateAuditEvent};
use crate::core::{ClientId, RealmId, UserId};
use crate::identity::IdentityEngine;
use crate::protocol::admin_auth::{AdminRateLimiter, RateLimitOutcome};
use crate::protocol::convert::identity::{
    proto_user_status_to_domain, realm_page_to_proto, user_bulk_result_to_proto,
    user_page_to_proto, void_bulk_result_to_proto,
};
use crate::protocol::convert::oauth::{
    client_page_to_proto, proto_authorize_to_domain, proto_client_creds_to_domain,
    proto_token_exchange_to_domain,
};
use crate::protocol::proto::identity::v1 as pb;
use crate::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupId, GroupMember, Permission,
    RbacEngine, RbacError, RoleId, Scope, Subject, UpdateGroupRequest, UpdateRoleRequest,
};

/// Default maximum request body size (1 MiB).
///
/// Covers normal JSON payloads (user/realm CRUD, OAuth token exchange).
/// Larger payloads are rejected with HTTP 413 (Payload Too Large) before
/// hitting any handler.
const BODY_LIMIT_DEFAULT: usize = 1024 * 1024;

/// Reduced body limit (64 KiB) for endpoints that only accept short codes
/// or token strings (e.g. introspection, revocation).
///
/// Defense-in-depth: these endpoints never legitimately receive payloads
/// anywhere near this size, so a stricter limit reduces the blast radius
/// of resource-exhaustion attempts.
const BODY_LIMIT_SMALL: usize = 64 * 1024;

/// Shared application state passed to all route handlers.
pub struct AppState {
    /// The identity engine for all domain operations.
    pub identity: Arc<dyn IdentityEngine>,
    /// The RBAC engine for role / group / assignment management.
    pub rbac: Arc<dyn RbacEngine>,
    /// The audit engine for mutation logging.
    pub audit: Arc<dyn AuditEngine>,
    /// Whether the server is running in development mode.
    ///
    /// Enables the `POST /admin/bootstrap` endpoint for SDK integration
    /// tests and local development.
    pub dev_mode: bool,
    /// Shared admin API rate limiter. Shared between the HTTP and gRPC
    /// admin surfaces so a caller cannot evade the limit by switching
    /// protocols.
    pub admin_rate_limiter: Arc<AdminRateLimiter>,
}

impl AppState {
    /// Creates a new `AppState` with all three engines.
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        Self {
            identity,
            rbac,
            audit,
            dev_mode: false,
            admin_rate_limiter: Arc::new(AdminRateLimiter::new()),
        }
    }

    /// Creates a new `AppState` in development mode.
    ///
    /// Enables the `POST /admin/bootstrap` endpoint.
    pub fn new_dev(
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        Self {
            identity,
            rbac,
            audit,
            dev_mode: true,
            admin_rate_limiter: Arc::new(AdminRateLimiter::new()),
        }
    }

    /// Creates an `AppState` that shares an existing rate limiter.
    ///
    /// Used when wiring the gRPC server so its interceptor sees the same
    /// per-user counts as the HTTP handlers.
    pub fn with_shared_rate_limiter(
        identity: Arc<dyn IdentityEngine>,
        rbac: Arc<dyn RbacEngine>,
        audit: Arc<dyn AuditEngine>,
        admin_rate_limiter: Arc<AdminRateLimiter>,
    ) -> Self {
        Self {
            identity,
            rbac,
            audit,
            dev_mode: false,
            admin_rate_limiter,
        }
    }
}

/// Authenticated admin context extracted from request headers.
///
/// Contains the realm and user that passed both token validation
/// and the `hearth.admin` permission check.
#[derive(Debug, Clone)]
pub(crate) struct AdminAuth {
    pub(crate) realm_id: RealmId,
    pub(crate) user_id: UserId,
}

/// Extracts and validates admin authentication from request headers.
///
/// 1. Extracts `Authorization: Bearer <token>` and `X-Realm-ID`
/// 2. Validates the token via `identity.validate_token()`
/// 3. Checks `hearth.admin` appears in the token's `permissions` claim
/// 4. Checks rate limit (100 req/min per admin user)
pub(crate) fn extract_admin_auth(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AdminAuth, (StatusCode, Json<serde_json::Value>)> {
    let realm_id = extract_realm_id(headers)?;

    // Extract bearer token
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "missing authorization header"})),
            )
        })?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid authorization header"})),
            )
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid authorization scheme"})),
        )
    })?;

    // Validate token
    let claims = state
        .identity
        .validate_token(&realm_id, token)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid token"})),
            )
        })?;

    // sub is "user_{uuid}" — strip prefix to get raw UUID
    let uuid_str = claims.sub.strip_prefix("user_").unwrap_or(&claims.sub);
    let user_uuid: uuid::Uuid = uuid_str.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid token"})),
        )
    })?;
    let user_id = UserId::new(user_uuid);

    // Check admin role via the token's `permissions` claim (§ 5.2).
    let is_admin = claims.permissions.iter().any(|p| p == "hearth.admin");
    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        ));
    }

    // Rate limiting
    check_admin_rate_limit(state, &user_id)?;

    Ok(AdminAuth { realm_id, user_id })
}

/// Checks the admin API rate limit for a user.
///
/// Returns 429 if the user has exceeded 100 requests in the current
/// 1-minute window.
fn check_admin_rate_limit(
    state: &AppState,
    user_id: &UserId,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    #[allow(clippy::cast_possible_truncation)]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    match state.admin_rate_limiter.check(user_id, now) {
        RateLimitOutcome::Allowed => Ok(()),
        RateLimitOutcome::Exceeded => Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "rate limit exceeded"})),
        )),
    }
}

/// Builds the HTTP router with all configured routes.
///
/// The returned router is ready to be served with [`serve`].
pub fn router(state: Arc<AppState>) -> Router {
    let admin_routes = Router::new()
        .route(
            "/users",
            axum::routing::get(admin_list_users).post(admin_create_user),
        )
        .route("/users/bulk", axum::routing::post(admin_bulk_users))
        .route(
            "/users/{id}",
            axum::routing::get(admin_get_user)
                .put(admin_update_user)
                .delete(admin_delete_user),
        )
        .route(
            "/realms",
            axum::routing::get(admin_list_realms).post(admin_create_realm),
        )
        .route(
            "/realms/{id}",
            axum::routing::get(admin_get_realm)
                .put(admin_update_realm)
                .delete(admin_delete_realm),
        )
        .route(
            "/applications",
            axum::routing::get(admin_list_clients).post(admin_register_client),
        )
        .route(
            "/applications/{id}",
            axum::routing::get(admin_get_client)
                .put(admin_update_client)
                .delete(admin_delete_client),
        )
        .route(
            "/users/{id}/consents",
            axum::routing::get(admin_list_user_consents),
        )
        .route(
            "/users/{id}/consents/{client_id}",
            axum::routing::delete(admin_revoke_user_consent),
        )
        .route("/audit", axum::routing::get(admin_list_audit))
        .route(
            "/roles",
            axum::routing::get(admin_list_roles).post(admin_create_role),
        )
        .route(
            "/roles/{id}",
            axum::routing::get(admin_get_role)
                .put(admin_update_role)
                .delete(admin_delete_role),
        )
        .route(
            "/groups",
            axum::routing::get(admin_list_groups).post(admin_create_group),
        )
        .route(
            "/groups/{id}",
            axum::routing::get(admin_get_group)
                .put(admin_update_group)
                .delete(admin_delete_group),
        )
        .route(
            "/groups/{id}/members",
            axum::routing::get(admin_list_group_members).post(admin_add_group_member),
        )
        .route(
            "/groups/{id}/members/{member_id}",
            axum::routing::delete(admin_remove_group_member),
        )
        .route(
            "/users/{id}/roles",
            axum::routing::get(admin_list_user_assignments).post(admin_assign_role),
        )
        .route(
            "/assignments/{id}",
            axum::routing::delete(admin_unassign_role),
        );

    Router::new()
        .route("/health", axum::routing::get(health))
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(oidc_discovery),
        )
        .route("/jwks", axum::routing::get(jwks))
        .route("/users", axum::routing::post(create_user))
        .route("/clients", axum::routing::post(register_client))
        .route("/authorize", axum::routing::post(authorize))
        .route("/token", axum::routing::post(token_exchange))
        .route(
            "/revoke",
            axum::routing::post(token_revocation)
                .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
        )
        .route(
            "/introspect",
            axum::routing::post(token_introspection)
                .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
        )
        .route(
            "/device_authorization",
            axum::routing::post(device_authorization),
        )
        .route("/userinfo", axum::routing::get(userinfo))
        .route("/v1/me/permissions", axum::routing::get(me_permissions))
        .route("/oauth/consents", axum::routing::get(self_list_consents))
        .route(
            "/oauth/consents/{client_id}",
            axum::routing::delete(self_revoke_consent),
        )
        .nest("/admin", admin_routes)
        .route("/admin/bootstrap", axum::routing::post(admin_bootstrap))
        .nest("/scim/v2", crate::protocol::scim::router())
        .layer(DefaultBodyLimit::max(BODY_LIMIT_DEFAULT))
        .with_state(state)
}

/// Starts the HTTP server on the given address.
///
/// Binds to the specified address and serves requests until the provided
/// shutdown signal resolves. Returns an error if binding or serving fails.
pub async fn serve(
    addr: SocketAddr,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    serve_router(addr, router(state), shutdown).await
}

/// Starts the HTTP server on the given address with a pre-built router.
///
/// Variant of [`serve`] that accepts an already-assembled axum [`Router`]
/// so callers can merge in additional routers (e.g. the web UI adapter
/// under `/ui/*`) before handing the final tree to axum.
///
/// # Errors
///
/// Returns the same errors as [`serve`].
pub async fn serve_router(
    addr: SocketAddr,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    info!(%local_addr, "HTTP server listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;

    Ok(())
}

/// Starts the HTTPS server on a pre-bound listener with TLS termination.
///
/// Accepts TCP connections, performs TLS handshakes using the provided
/// `TlsAcceptor`, then serves HTTP/1.1 and HTTP/2 requests via the axum
/// router. Each connection is spawned independently — a failed handshake
/// does not block other connections.
pub async fn serve_tls(
    listener: TcpListener,
    state: Arc<AppState>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> Result<(), std::io::Error> {
    serve_tls_router(listener, router(state), tls_acceptor, shutdown).await
}

/// Starts the HTTPS server with a pre-built router.
///
/// Variant of [`serve_tls`] that accepts an already-assembled axum
/// [`Router`] so callers can merge in additional routers (e.g. the web
/// UI adapter under `/ui/*`) before handing the final tree to axum.
///
/// # Errors
///
/// Returns the same errors as [`serve_tls`].
pub async fn serve_tls_router(
    listener: TcpListener,
    app: Router,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> Result<(), std::io::Error> {
    let local_addr = listener.local_addr()?;

    info!(%local_addr, "HTTPS server listening");

    let mut shutdown_rx = shutdown;
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(error = %e, "failed to accept TCP connection");
                        continue;
                    }
                };

                let acceptor = tls_acceptor.clone();
                let app = app.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                            return;
                        }
                    };

                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(
                        app.into_service(),
                    );

                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        debug!(peer = %peer_addr, error = %e, "connection error");
                    }
                });
            }
            _ = shutdown_rx.changed() => {
                info!("HTTPS server shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Starts an HTTP server that redirects all requests to HTTPS via 301.
///
/// Binds to the specified address and responds to every request with a
/// `301 Moved Permanently` redirect to the HTTPS equivalent URL on the
/// given `https_port`.
pub async fn serve_redirect(
    addr: SocketAddr,
    https_port: u16,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let app = Router::new().fallback(move |req: axum::extract::Request| async move {
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        // Strip port from host if present
        let hostname = host.split(':').next().unwrap_or(host);
        let path = req.uri().path();
        let query = req
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();

        let location = if https_port == 443 {
            format!("https://{hostname}{path}{query}")
        } else {
            format!("https://{hostname}:{https_port}{path}{query}")
        };

        (
            StatusCode::MOVED_PERMANENTLY,
            [(axum::http::header::LOCATION, location)],
        )
    });

    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    info!(%local_addr, "HTTP→HTTPS redirect server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}

// === JSON helpers ===

/// Serializes a proto type to a `serde_json::Value` with int64 fields
/// emitted as JSON numbers instead of strings.
///
/// pbjson follows the proto3 JSON mapping spec which encodes int64/uint64
/// as strings to avoid IEEE 754 precision loss. REST APIs conventionally
/// use numeric JSON values, so this helper post-processes the serialized
/// JSON to convert string-encoded integers back to numbers.
fn proto_to_rest_json<T: Serialize>(value: &T) -> serde_json::Value {
    let v = serde_json::to_value(value).unwrap_or_default();
    coerce_string_ints(v)
}

/// Recursively converts string values that represent integers to JSON numbers.
fn coerce_string_ints(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(ref s) => {
            if let Ok(n) = s.parse::<i64>() {
                serde_json::Value::Number(n.into())
            } else {
                v
            }
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, coerce_string_ints(v)))
                .collect(),
        ),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(coerce_string_ints).collect())
        }
        other => other,
    }
}

// === Route handlers ===

/// Health check endpoint.
///
/// Returns 200 OK with a JSON body indicating the server is healthy.
/// Used by load balancers, monitoring, and CLI integration tests.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// OIDC Discovery endpoint.
///
/// Returns the `OpenID` Connect Discovery 1.0 document describing the
/// provider's configuration, endpoints, and supported features.
async fn oidc_discovery(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let doc = state.identity.oidc_discovery();
    (
        StatusCode::OK,
        Json(proto_to_rest_json(&pb::OidcDiscoveryDocument::from(&doc))),
    )
}

/// JWKS endpoint.
///
/// Returns the JSON Web Key Set containing the server's public signing
/// keys for external token verification.
async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let doc = state.identity.jwks();
    (
        StatusCode::OK,
        Json(proto_to_rest_json(&pb::JwksDocument::from(&doc))),
    )
}

// === User management endpoints ===

/// Create a new user.
///
/// Requires `X-Realm-ID` header. Returns the created user record.
async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::CreateUserRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::CreateUserRequest::from(body);

    match state.identity.create_user(&realm_id, &request) {
        Ok(user) => (
            StatusCode::CREATED,
            Json(proto_to_rest_json(&pb::User::from(&user))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === OIDC / OAuth 2.0 endpoints ===

/// HTTP request body for token exchange.
///
/// Uses a flat struct because the proto `TokenExchangeRequest` doesn't cover
/// the multi-grant-type dispatch (`authorization_code` vs `refresh_token`).
#[derive(Debug, Deserialize)]
struct HttpTokenRequest {
    client_id: String,
    #[serde(default)]
    grant_type: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    // Client credentials fields
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    // Device code field
    #[serde(default)]
    device_code: Option<String>,
}

/// Extracts a `RealmId` from the `X-Realm-ID` header.
///
/// Returns a `(StatusCode, Json)` error if the header is missing or invalid.
fn extract_realm_id(headers: &HeaderMap) -> Result<RealmId, (StatusCode, Json<serde_json::Value>)> {
    let header_value = headers
        .get("x-realm-id")
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing X-Realm-ID header"})),
            )
        })?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid X-Realm-ID header"})),
            )
        })?;

    let uuid: uuid::Uuid = header_value.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "X-Realm-ID must be a valid UUID"})),
        )
    })?;

    Ok(RealmId::new(uuid))
}

/// Maps an `IdentityError` to an HTTP status code and safe error message.
///
/// Error messages are intentionally vague to prevent information leakage
/// per the cross-cutting security requirements.
fn identity_error_to_response(
    err: &crate::identity::IdentityError,
) -> (StatusCode, Json<serde_json::Value>) {
    use crate::identity::IdentityError;

    let (status, message) = match err {
        IdentityError::RealmNotFound | IdentityError::UserNotFound => {
            (StatusCode::NOT_FOUND, "not found")
        }
        IdentityError::RealmSuspended => (StatusCode::FORBIDDEN, "realm suspended"),
        IdentityError::DuplicateRealmName => (StatusCode::CONFLICT, "duplicate realm name"),
        IdentityError::DuplicateEmail => (StatusCode::CONFLICT, "duplicate email"),
        IdentityError::InvalidInput { .. } => (StatusCode::BAD_REQUEST, "invalid input"),
        IdentityError::CredentialNotFound => (StatusCode::NOT_FOUND, "credential not found"),
        IdentityError::InvalidCredential { .. } => (StatusCode::UNAUTHORIZED, "invalid credential"),
        IdentityError::SessionNotFound => (StatusCode::NOT_FOUND, "session not found"),
        IdentityError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid token"),
        IdentityError::TokenExpired => (StatusCode::UNAUTHORIZED, "token expired"),
        IdentityError::InvalidClient => (StatusCode::BAD_REQUEST, "invalid client"),
        IdentityError::InvalidRedirectUri => (StatusCode::BAD_REQUEST, "invalid redirect URI"),
        IdentityError::InvalidAuthorizationCode => {
            (StatusCode::BAD_REQUEST, "invalid authorization code")
        }
        IdentityError::InvalidGrant { .. } => (StatusCode::BAD_REQUEST, "invalid grant"),
        IdentityError::InvalidClientSecret => (StatusCode::UNAUTHORIZED, "invalid client"),
        IdentityError::AuthorizationPending => (StatusCode::BAD_REQUEST, "authorization_pending"),
        IdentityError::SlowDown => (StatusCode::BAD_REQUEST, "slow_down"),
        IdentityError::DeviceCodeExpired => (StatusCode::BAD_REQUEST, "expired_token"),
        IdentityError::DeviceCodeDenied => (StatusCode::BAD_REQUEST, "access_denied"),
        IdentityError::TokenRevoked => (StatusCode::UNAUTHORIZED, "token revoked"),
        IdentityError::UnsupportedGrantType => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        IdentityError::MfaRequired => (StatusCode::FORBIDDEN, "MFA verification required"),
        IdentityError::InvalidMfaCode => (StatusCode::UNAUTHORIZED, "invalid MFA code"),
        IdentityError::MfaNotEnabled => (StatusCode::BAD_REQUEST, "MFA not enabled"),
        IdentityError::MfaAlreadyEnabled => (StatusCode::CONFLICT, "MFA already enabled"),
        IdentityError::WebAuthnRegistrationFailed { .. } => {
            (StatusCode::BAD_REQUEST, "webauthn registration failed")
        }
        IdentityError::WebAuthnAuthenticationFailed { .. } => {
            (StatusCode::UNAUTHORIZED, "webauthn authentication failed")
        }
        IdentityError::WebAuthnCredentialNotFound => {
            (StatusCode::NOT_FOUND, "credential not found")
        }
        IdentityError::InvalidAttestation { .. } => {
            (StatusCode::BAD_REQUEST, "invalid attestation")
        }
        IdentityError::InvalidAssertion { .. } => (StatusCode::UNAUTHORIZED, "invalid assertion"),
        IdentityError::Unauthorized => (StatusCode::FORBIDDEN, "forbidden"),
        IdentityError::ClientNotFound => (StatusCode::NOT_FOUND, "not found"),
        IdentityError::MagicLinkTokenInvalid => {
            (StatusCode::UNAUTHORIZED, "invalid or expired link")
        }
        IdentityError::VerificationTokenInvalid => {
            (StatusCode::GONE, "invalid or expired verification link")
        }
        IdentityError::PasswordResetTokenInvalid => {
            (StatusCode::UNAUTHORIZED, "invalid or expired reset link")
        }
        IdentityError::UserNotVerified => (StatusCode::FORBIDDEN, "email not verified"),
        IdentityError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "too many requests"),
        IdentityError::OrganizationNotFound => (StatusCode::NOT_FOUND, "organization not found"),
        IdentityError::DuplicateOrgSlug => (StatusCode::CONFLICT, "duplicate organization slug"),
        IdentityError::OrganizationSuspended => (StatusCode::FORBIDDEN, "organization suspended"),
        IdentityError::AlreadyMember => (StatusCode::CONFLICT, "already a member"),
        IdentityError::NotAMember => (StatusCode::NOT_FOUND, "not a member"),
        IdentityError::LastOwner => (StatusCode::CONFLICT, "cannot remove last owner"),
        IdentityError::MemberLimitReached => {
            (StatusCode::UNPROCESSABLE_ENTITY, "member limit reached")
        }
        IdentityError::InvitationInvalid => (StatusCode::BAD_REQUEST, "invalid invitation"),
        IdentityError::DuplicateInvitation => (StatusCode::CONFLICT, "duplicate invitation"),
        IdentityError::SystemRealmProtected { .. } => {
            (StatusCode::FORBIDDEN, "system realm is read-only")
        }
        IdentityError::RegistrationDisabled => (StatusCode::FORBIDDEN, "registration disabled"),
        IdentityError::RegistrationDomainNotAllowed { .. } => {
            (StatusCode::FORBIDDEN, "email domain not permitted")
        }
        IdentityError::RegistrationRequiresInvitation => {
            (StatusCode::FORBIDDEN, "invitation required")
        }
        IdentityError::ConsentRequired => (StatusCode::FORBIDDEN, "consent required"),
        IdentityError::ConsentTicketNotFound | IdentityError::ConsentTicketExpired => {
            (StatusCode::BAD_REQUEST, "consent ticket invalid")
        }
        IdentityError::ConsentScopeNotRequested => {
            (StatusCode::BAD_REQUEST, "scope not in original request")
        }
        IdentityError::ConsentNotFound => (StatusCode::NOT_FOUND, "consent not found"),
        IdentityError::FederationUnknownConnector => {
            (StatusCode::NOT_FOUND, "federation connector not found")
        }
        IdentityError::FederationInvalidState => {
            (StatusCode::BAD_REQUEST, "invalid federation state")
        }
        IdentityError::FederationUpstreamError { .. } => {
            (StatusCode::BAD_GATEWAY, "federation upstream error")
        }
        IdentityError::FederationTokenVerificationFailed => (
            StatusCode::UNAUTHORIZED,
            "federation token verification failed",
        ),
        IdentityError::FederationEmailNotVerified => {
            (StatusCode::FORBIDDEN, "upstream email not verified")
        }
        IdentityError::FederationLinkConfirmationRequired { .. } => {
            // Browser flows redirect to /ui/federation/confirm-link; JSON
            // callers (rare for federation) get a terse 409 so they know
            // a linking decision is required.
            (
                StatusCode::CONFLICT,
                "federation link confirmation required",
            )
        }
        IdentityError::FederationNotLinked => {
            (StatusCode::NOT_FOUND, "external identity not linked")
        }
        IdentityError::FederationAlreadyLinked => {
            (StatusCode::CONFLICT, "external identity already linked")
        }
        IdentityError::DuplicateScimExternalId => {
            (StatusCode::CONFLICT, "SCIM externalId already in use")
        }
        IdentityError::SamlParse { .. }
        | IdentityError::SamlSignature
        | IdentityError::SamlExpired
        | IdentityError::SamlReplay
        | IdentityError::SamlAudienceMismatch
        | IdentityError::SamlIssuerMismatch
        | IdentityError::SamlDestinationMismatch
        | IdentityError::SamlUnsupportedAlgorithm
        | IdentityError::SamlInvalidAuthnRequest { .. } => {
            (StatusCode::BAD_REQUEST, "invalid SAML message")
        }
        IdentityError::SamlMetadataFetch { .. } => {
            (StatusCode::BAD_GATEWAY, "SAML metadata fetch failed")
        }
        IdentityError::SamlUnknownSp | IdentityError::SamlUnknownIdp => {
            (StatusCode::NOT_FOUND, "SAML entity not found")
        }
        IdentityError::SigningError { .. }
        | IdentityError::Storage(_)
        | IdentityError::Serialization { .. }
        | IdentityError::Internal { .. }
        | IdentityError::ConfigInvalid { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
        IdentityError::TokenTooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, "token too large"),
        IdentityError::InvalidAttribute { .. } => (StatusCode::BAD_REQUEST, "invalid attribute"),
        IdentityError::AuditFailure { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error: audit record failed",
        ),
    };

    (status, Json(serde_json::json!({"error": message})))
}

/// Register an OAuth 2.0 client.
///
/// Requires `X-Realm-ID` header. Returns the created client record.
async fn register_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::RegisterClientRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;

    match state.identity.register_client(&realm_id, &request) {
        Ok(client) => (
            StatusCode::CREATED,
            Json(proto_to_rest_json(&pb::OAuthClient::from(&client))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Initiate an OAuth 2.0 authorization code flow.
///
/// Requires `X-Realm-ID` header. Returns an authorization code and state.
async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::AuthorizationRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = match proto_authorize_to_domain(body) {
        Ok(r) => r,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
                .into_response();
        }
    };

    match state.identity.authorize(&realm_id, &request) {
        Ok(response) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::AuthorizationResponse::from(
                &response,
            ))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Exchange an authorization code or refresh token for tokens.
///
/// Requires `X-Realm-ID` header.
///
/// Supports multiple grant types:
/// - `authorization_code` (default): exchange a code for access, ID, and refresh tokens
/// - `refresh_token`: exchange a refresh token for a new token pair
/// - `client_credentials`: issue an access token for a confidential client
/// - `urn:ietf:params:oauth:grant-type:device_code`: poll for device authorization
#[allow(clippy::too_many_lines)]
async fn token_exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpTokenRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let grant_type = body.grant_type.as_deref().unwrap_or("authorization_code");

    match grant_type {
        "authorization_code" => {
            let (Some(code), Some(redirect_uri)) = (body.code, body.redirect_uri) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "code and redirect_uri required for authorization_code grant"})),
                )
                    .into_response();
            };

            let proto_req = pb::TokenExchangeRequest {
                client_id: body.client_id,
                code,
                redirect_uri,
                code_verifier: body.code_verifier,
            };

            let request = match proto_token_exchange_to_domain(&proto_req) {
                Ok(r) => r,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": msg})),
                    )
                        .into_response();
                }
            };

            match state
                .identity
                .exchange_authorization_code(&realm_id, &request)
            {
                Ok(response) => (
                    StatusCode::OK,
                    Json(proto_to_rest_json(&pb::OidcTokenResponse::from(&response))),
                )
                    .into_response(),
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "refresh_token" => {
            let Some(refresh_token) = body.refresh_token else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "refresh_token required for refresh_token grant"})),
                )
                    .into_response();
            };

            match state.identity.refresh_tokens(&realm_id, &refresh_token) {
                Ok(tokens) => {
                    let resp = pb::OidcTokenResponse {
                        access_token: tokens.access_token().to_string(),
                        id_token: String::new(),
                        token_type: "Bearer".to_string(),
                        expires_in: 900,
                        refresh_token: tokens.refresh_token().to_string(),
                    };
                    (StatusCode::OK, Json(proto_to_rest_json(&resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "client_credentials" => {
            let proto_req = pb::ClientCredentialsRequest {
                client_id: body.client_id,
                client_secret: body.client_secret.unwrap_or_default(),
                scope: body.scope,
            };

            let request = match proto_client_creds_to_domain(&proto_req) {
                Ok(r) => r,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": msg})),
                    )
                        .into_response();
                }
            };

            match state.identity.client_credentials_token(&realm_id, &request) {
                Ok(response) => (
                    StatusCode::OK,
                    Json(proto_to_rest_json(&pb::ClientCredentialsResponse::from(
                        &response,
                    ))),
                )
                    .into_response(),
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let Some(device_code) = body.device_code else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({"error": "device_code required for device_code grant"}),
                    ),
                )
                    .into_response();
            };

            let client_id = match body.client_id.parse::<uuid::Uuid>() {
                Ok(u) => ClientId::new(u),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid client_id UUID"})),
                    )
                        .into_response();
                }
            };

            match state
                .identity
                .poll_device_token(&realm_id, &device_code, &client_id)
            {
                Ok(response) => (
                    StatusCode::OK,
                    Json(proto_to_rest_json(&pb::OidcTokenResponse::from(&response))),
                )
                    .into_response(),
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unsupported_grant_type"})),
        )
            .into_response(),
    }
}

// === Token Revocation (RFC 7009) ===

/// POST /revoke — revokes an OAuth 2.0 token.
///
/// Per RFC 7009, returns 200 OK regardless of whether the token was
/// actually revoked (to prevent information leakage).
async fn token_revocation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::TokenRevocationRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::TokenRevocationRequest::from(body);

    match state.identity.revoke_token(&realm_id, &request) {
        Ok(()) | Err(crate::identity::IdentityError::InvalidToken) => {
            // RFC 7009: always return 200 OK
            StatusCode::OK.into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Token Introspection (RFC 7662) ===

/// POST /introspect — introspects an OAuth 2.0 token.
///
/// Returns metadata about the token including its active status.
async fn token_introspection(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::TokenIntrospectionRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::TokenIntrospectionRequest::from(body);

    match state.identity.introspect_token(&realm_id, &request) {
        Ok(response) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::IntrospectionResponse::from(
                &response,
            ))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Device Authorization (RFC 8628) ===

/// POST `/device_authorization` — initiates a device authorization flow.
///
/// Returns a device code, user code, and verification URI.
async fn device_authorization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::DeviceAuthorizationRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let client_id = match body.client_id.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client_id UUID"})),
            )
                .into_response();
        }
    };

    let request = crate::identity::DeviceAuthorizationRequest {
        client_id,
        scope: body.scope,
    };

    match state.identity.device_authorize(&realm_id, &request) {
        Ok(response) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::DeviceAuthorizationResponse::from(
                &response,
            ))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === UserInfo endpoint (OIDC Core §5.3) ===

/// GET /userinfo — returns claims about the authenticated user.
async fn userinfo(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Extract Bearer token from Authorization header
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response();
    };

    match state.identity.userinfo(&realm_id, token) {
        Ok(info) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::UserInfoResponse::from(&info))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Claims-based permissions endpoint ===

/// Response body for `GET /v1/me/permissions`.
#[derive(Debug, Serialize)]
struct MePermissionsResponse {
    /// The effective role names granted to the caller.
    roles: Vec<String>,
    /// The effective group slugs the caller belongs to.
    groups: Vec<String>,
    /// The effective permissions (sorted, de-duplicated).
    permissions: Vec<String>,
    /// Echoes the scope the caller requested, if any.
    scope: Option<String>,
}

/// `GET /v1/me/permissions` — resolves and returns the authenticated user's
/// effective roles, groups, and permissions FRESHLY (not from the JWT).
///
/// Accepts optional `org_id` and `scope` query parameters.
async fn me_permissions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response();
    };

    let claims = match state.identity.validate_token(&realm_id, token) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response();
        }
    };

    let uuid_str = claims.sub.strip_prefix("user_").unwrap_or(&claims.sub);
    let user_uuid: uuid::Uuid = match uuid_str.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response();
        }
    };
    let user_id = UserId::new(user_uuid);

    let org_id = params.get("org_id").and_then(|s| {
        uuid::Uuid::parse_str(s)
            .ok()
            .map(crate::core::OrganizationId::new)
    });
    let scope = params.get("scope").cloned();

    let resolved =
        match state
            .rbac
            .resolve_permissions(&user_id, &realm_id, org_id.as_ref(), scope.as_deref())
        {
            Ok(r) => r,
            Err(e) => return rbac_error_to_response(&e).into_response(),
        };

    (
        StatusCode::OK,
        Json(MePermissionsResponse {
            roles: resolved.roles,
            groups: resolved.groups,
            permissions: resolved
                .permissions
                .into_iter()
                .map(|p| p.into_string())
                .collect(),
            scope,
        }),
    )
        .into_response()
}

/// Maps [`RbacError`] values to HTTP responses.
fn rbac_error_to_response(err: &RbacError) -> (StatusCode, Json<serde_json::Value>) {
    let (status, code) = match err {
        RbacError::RoleNotFound | RbacError::GroupNotFound | RbacError::AssignmentNotFound => {
            (StatusCode::NOT_FOUND, "not_found")
        }
        RbacError::DuplicateRoleName | RbacError::DuplicateGroupSlug => {
            (StatusCode::CONFLICT, "already_exists")
        }
        RbacError::InvalidPermission { .. }
        | RbacError::InvalidRoleName { .. }
        | RbacError::InvalidGroupSlug { .. } => (StatusCode::BAD_REQUEST, "invalid_request"),
        RbacError::CycleDetected { .. } => (StatusCode::BAD_REQUEST, "cycle_detected"),
        RbacError::DepthExceeded { .. }
        | RbacError::BreadthExceeded { .. }
        | RbacError::TokenSizeExceeded { .. } => {
            (StatusCode::PAYLOAD_TOO_LARGE, "resource_exhausted")
        }
        RbacError::ReservedNamespace { .. } => (StatusCode::FORBIDDEN, "reserved_namespace"),
        RbacError::InvalidScope { .. } => (StatusCode::BAD_REQUEST, "invalid_scope"),
        RbacError::Storage(_) | RbacError::Serialization { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    };
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "error_description": err.to_string(),
        })),
    )
}

/// Pagination query parameters.
#[derive(Debug, Deserialize)]
struct PaginationParams {
    cursor: Option<String>,
    limit: Option<usize>,
}

impl PaginationParams {
    /// Returns the limit clamped to [1, 100] with a default of 20.
    fn effective_limit(&self) -> usize {
        self.limit.unwrap_or(20).clamp(1, 100)
    }
}

/// Admin: list users (paginated).
async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    match state.identity.list_users(
        &auth.realm_id,
        params.cursor.as_deref(),
        params.effective_limit(),
    ) {
        Ok(page) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&user_page_to_proto(&page))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: create user.
async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::CreateUserRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::CreateUserRequest::from(body);

    match state.identity.create_user(&auth.realm_id, &request) {
        Ok(user) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: user.id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (
                StatusCode::CREATED,
                Json(proto_to_rest_json(&pb::User::from(&user))),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: get user by ID.
async fn admin_get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let user_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user ID"})),
            )
                .into_response()
        }
    };

    match state
        .identity
        .get_user(&auth.realm_id, &UserId::new(user_uuid))
    {
        Ok(Some(user)) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::User::from(&user))),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: update user by ID.
async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<pb::UpdateUserRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let user_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user ID"})),
            )
                .into_response()
        }
    };

    // Validate status if provided
    if let Some(status_val) = body.status {
        if proto_user_status_to_domain(status_val).is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid status"})),
            )
                .into_response();
        }
    }

    let request = crate::identity::UpdateUserRequest::from(body);
    let uid = UserId::new(user_uuid);

    match state.identity.update_user(&auth.realm_id, &uid, &request) {
        Ok(user) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::UserUpdated,
                resource_type: "user".to_string(),
                resource_id: uid.as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (
                StatusCode::OK,
                Json(proto_to_rest_json(&pb::User::from(&user))),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: delete user by ID.
async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let user_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user ID"})),
            )
                .into_response()
        }
    };

    match state
        .identity
        .delete_user(&auth.realm_id, &UserId::new(user_uuid))
    {
        Ok(()) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::UserDeleted,
                resource_type: "user".to_string(),
                resource_id: user_uuid.to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// HTTP request body for bulk user operations.
#[derive(Debug, Deserialize)]
struct HttpBulkUsersRequest {
    operation: String,
    #[serde(default)]
    users: Vec<pb::CreateUserRequest>,
    #[serde(default)]
    user_ids: Vec<String>,
}

/// Admin: bulk user operations (create or disable).
#[allow(clippy::too_many_lines)]
async fn admin_bulk_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpBulkUsersRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    match body.operation.as_str() {
        "create" => {
            let requests: Vec<crate::identity::CreateUserRequest> = body
                .users
                .into_iter()
                .map(crate::identity::CreateUserRequest::from)
                .collect();

            match state.identity.bulk_create_users(&auth.realm_id, &requests) {
                Ok(results) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        realm_id: auth.realm_id.clone(),
                        actor: auth.user_id.as_uuid().to_string(),
                        action: crate::audit::AuditAction::BulkUsersCreated,
                        resource_type: "user".to_string(),
                        resource_id: format!("batch:{}", results.len()),
                        metadata: Some(serde_json::json!({"via": "admin_api"})),
                    });

                    let proto_results: Vec<_> =
                        results.iter().map(user_bulk_result_to_proto).collect();

                    (
                        StatusCode::OK,
                        Json(proto_to_rest_json(&pb::BulkResult {
                            results: proto_results,
                        })),
                    )
                        .into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "disable" => {
            let mut user_ids = Vec::new();
            for id_str in &body.user_ids {
                match id_str.parse::<uuid::Uuid>() {
                    Ok(uuid) => user_ids.push(UserId::new(uuid)),
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error": "invalid user ID in list"})),
                        )
                            .into_response()
                    }
                }
            }

            match state.identity.bulk_disable_users(&auth.realm_id, &user_ids) {
                Ok(results) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        realm_id: auth.realm_id.clone(),
                        actor: auth.user_id.as_uuid().to_string(),
                        action: crate::audit::AuditAction::BulkUsersDisabled,
                        resource_type: "user".to_string(),
                        resource_id: format!("batch:{}", results.len()),
                        metadata: Some(serde_json::json!({"via": "admin_api"})),
                    });

                    let proto_results: Vec<_> =
                        results.iter().map(void_bulk_result_to_proto).collect();

                    (
                        StatusCode::OK,
                        Json(proto_to_rest_json(&pb::BulkResult {
                            results: proto_results,
                        })),
                    )
                        .into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid operation, expected 'create' or 'disable'"})),
        )
            .into_response(),
    }
}

/// Admin: list realms (paginated).
async fn admin_list_realms(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let _auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    match state
        .identity
        .list_realms(params.cursor.as_deref(), params.effective_limit())
    {
        Ok(page) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&realm_page_to_proto(&page))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: create realm — disabled; realms are managed via `hearth.yaml`.
async fn admin_create_realm() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "error": "method_not_allowed",
            "message": "Realms are managed via hearth.yaml. Remove this endpoint from your client."
        })),
    )
}

/// Admin: get realm by ID.
async fn admin_get_realm(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let realm_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm ID"})),
            )
                .into_response()
        }
    };

    match state.identity.get_realm(&RealmId::new(realm_uuid)) {
        Ok(Some(realm)) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::Realm::from(&realm))),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: update realm — disabled; realms are managed via `hearth.yaml`.
async fn admin_update_realm(Path(_id): Path<String>) -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "error": "method_not_allowed",
            "message": "Realms are managed via hearth.yaml. Remove this endpoint from your client."
        })),
    )
}

/// Admin: delete realm by ID.
///
/// Only allows permanent deletion of realms with `Archived` status.
/// Active or Suspended realms must first be removed from `hearth.yaml`
/// and the server restarted (which archives them via reconciliation).
async fn admin_delete_realm(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let realm_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid realm ID"})),
            )
                .into_response()
        }
    };

    let tid = RealmId::new(realm_uuid);

    // Check realm status — only Archived realms can be permanently deleted.
    match state.identity.get_realm(&tid) {
        Ok(Some(realm))
            if realm.status() == crate::identity::RealmStatus::Archived =>
        {
            match state.identity.delete_realm(&tid) {
                Ok(()) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        realm_id: auth.realm_id.clone(),
                        actor: auth.user_id.as_uuid().to_string(),
                        action: crate::audit::AuditAction::RealmDeleted,
                        resource_type: "realm".to_string(),
                        resource_id: realm_uuid.to_string(),
                        metadata: Some(serde_json::json!({"via": "admin_api"})),
                    });
                    StatusCode::NO_CONTENT.into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        Ok(Some(_)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "conflict",
                "message": "Only archived realms can be permanently deleted. Remove the realm from hearth.yaml and restart to archive it first."
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: list clients (paginated).
async fn admin_list_clients(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    match state.identity.list_clients(
        &auth.realm_id,
        params.cursor.as_deref(),
        params.effective_limit(),
    ) {
        Ok(page) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&client_page_to_proto(&page))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: register a new client.
async fn admin_register_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::RegisterClientRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;

    match state.identity.register_client(&auth.realm_id, &request) {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ClientRegistered,
                resource_type: "client".to_string(),
                resource_id: client.client_id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (
                StatusCode::CREATED,
                Json(proto_to_rest_json(&pb::OAuthClient::from(&client))),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: get client by ID.
async fn admin_get_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let client_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client ID"})),
            )
                .into_response()
        }
    };

    match state
        .identity
        .get_client(&auth.realm_id, &ClientId::new(client_uuid))
    {
        Ok(Some(client)) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::OAuthClient::from(&client))),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: update client by ID.
async fn admin_update_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<pb::UpdateClientRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let client_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client ID"})),
            )
                .into_response()
        }
    };

    let request = crate::identity::UpdateClientRequest::from(body);

    match state
        .identity
        .update_client(&auth.realm_id, &ClientId::new(client_uuid), &request)
    {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ClientUpdated,
                resource_type: "client".to_string(),
                resource_id: client_uuid.to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (
                StatusCode::OK,
                Json(proto_to_rest_json(&pb::OAuthClient::from(&client))),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: delete client by ID.
async fn admin_delete_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let client_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client ID"})),
            )
                .into_response()
        }
    };

    match state
        .identity
        .delete_client(&auth.realm_id, &ClientId::new(client_uuid))
    {
        Ok(()) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ClientDeleted,
                resource_type: "client".to_string(),
                resource_id: client_uuid.to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Audit Endpoint ===

/// Query params for `GET /admin/audit`.
#[derive(Debug, Deserialize)]
struct AuditQueryParams {
    /// Filter by actor UUID (as string).
    actor: Option<String>,
    /// Filter by action name (e.g. `user_created`).
    action: Option<String>,
    /// Start of time window (inclusive, Unix micros).
    start_time: Option<i64>,
    /// End of time window (exclusive, Unix micros).
    end_time: Option<i64>,
    /// Maximum number of events to return (default 50).
    limit: Option<usize>,
}

/// `GET /admin/audit` — queries the audit log.
async fn admin_list_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<AuditQueryParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let action = params
        .action
        .as_deref()
        .and_then(|s| s.parse::<crate::audit::AuditAction>().ok());

    let query = crate::audit::AuditQuery {
        realm_id: auth.realm_id.clone(),
        start_time: params.start_time.map(crate::core::Timestamp::from_micros),
        end_time: params.end_time.map(crate::core::Timestamp::from_micros),
        actor: params.actor,
        action,
        limit: Some(params.limit.unwrap_or(50).min(200)),
    };

    match state.audit.query(&query) {
        Ok(events) => (
            StatusCode::OK,
            Json(serde_json::json!({ "events": events })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "audit query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "audit query failed"})),
            )
                .into_response()
        }
    }
}

// === OAuth Consent (self-service + admin) ===

/// Extracts the authenticated user from a Bearer access token. Returns
/// the user's [`UserId`] on success, or the appropriate error response.
fn extract_user_auth(
    headers: &HeaderMap,
    state: &AppState,
    realm_id: &RealmId,
) -> Result<UserId, (StatusCode, Json<serde_json::Value>)> {
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        ));
    };

    let claims = state
        .identity
        .validate_token(realm_id, token)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
        })?;

    uuid::Uuid::parse_str(&claims.sub)
        .map(UserId::new)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
        })
}

/// `GET /oauth/consents` — lists the current user's consents.
async fn self_list_consents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    match state.identity.list_consents_by_user(&realm_id, &user_id) {
        Ok(entries) => {
            let body = serde_json::json!({
                "items": entries.iter().map(|e| serde_json::json!({
                    "client_id": e.record.client_id.as_uuid().to_string(),
                    "client_name": e.client_name,
                    "client_logo_url": e.client_logo_url,
                    "scopes": e.record.granted_scopes,
                    "granted_at": e.record.granted_at.as_micros(),
                    "updated_at": e.record.updated_at.as_micros(),
                })).collect::<Vec<_>>(),
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /oauth/consents/{client_id}` — revokes the current user's
/// consent for a specific client.
async fn self_revoke_consent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(client_id_str): axum::extract::Path<String>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = client_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid client_id"})),
        )
            .into_response();
    };
    let client_id = crate::core::ClientId::new(uuid);
    match state
        .identity
        .revoke_consent(&realm_id, &user_id, &client_id)
    {
        Ok(()) => {
            // Engine now emits ConsentRevoked internally.
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /admin/users/{id}/consents` — admin: list any user's consents in
/// the admin's current realm.
async fn admin_list_user_consents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(user_id_str): axum::extract::Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = user_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid user_id"})),
        )
            .into_response();
    };
    let user_id = UserId::new(uuid);
    match state
        .identity
        .list_consents_by_user(&auth.realm_id, &user_id)
    {
        Ok(entries) => {
            let body = serde_json::json!({
                "items": entries.iter().map(|e| serde_json::json!({
                    "client_id": e.record.client_id.as_uuid().to_string(),
                    "client_name": e.client_name,
                    "client_logo_url": e.client_logo_url,
                    "scopes": e.record.granted_scopes,
                    "granted_at": e.record.granted_at.as_micros(),
                    "updated_at": e.record.updated_at.as_micros(),
                })).collect::<Vec<_>>(),
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /admin/users/{id}/consents/{client_id}` — admin revoke on
/// behalf of a user.
async fn admin_revoke_user_consent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path((user_id_str, client_id_str)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid_u) = user_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid user_id"})),
        )
            .into_response();
    };
    let Ok(uuid_c) = client_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid client_id"})),
        )
            .into_response();
    };
    let user_id = UserId::new(uuid_u);
    let client_id = crate::core::ClientId::new(uuid_c);
    match state
        .identity
        .revoke_consent(&auth.realm_id, &user_id, &client_id)
    {
        Ok(()) => {
            let _ = state.audit.append(&crate::audit::CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ConsentRevoked,
                resource_type: "oauth_client".to_string(),
                resource_id: client_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({
                    "via": "admin",
                    "target_user": user_id.as_uuid().to_string(),
                    "client_id": client_id.as_uuid().to_string(),
                })),
            });
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Dev Bootstrap Endpoint ===

/// POST /admin/bootstrap — creates a realm, admin user, session, assigns
/// the admin role, and issues tokens. Returns everything needed for SDK tests.
///
/// Only available when `AppState.dev_mode` is `true` (i.e., `--dev` flag).
/// Returns 404 in production mode.
async fn admin_bootstrap(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if !state.dev_mode {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response();
    }

    // Create realm
    let realm = match state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: "dev-realm".to_string(),
            config: None,
        }) {
        Ok(t) => t,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let realm_id = realm.id().clone();

    // Seed RBAC defaults on the new realm. Logged-only on failure so the
    // dev bootstrap doesn't brick on a storage blip — the realm record
    // already exists and seeding is idempotent.
    if let Err(e) = state.rbac.seed_realm(&realm_id) {
        tracing::warn!(error = %e, "dev bootstrap: RBAC seed failed");
    }

    // Create admin user
    let user = match state.identity.create_user(
        &realm_id,
        &crate::identity::CreateUserRequest {
            email: "admin@dev.local".to_string(),
            display_name: "Dev Admin".to_string(),
            ..Default::default()
        },
    ) {
        Ok(u) => u,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let user_id = user.id().clone();

    // Grant the realm.admin role to the admin user BEFORE issuing tokens so
    // the access-token `permissions` claim contains `hearth.admin` — otherwise
    // the returned token would be unable to call any admin endpoint.
    let admin_role = match state.rbac.get_role_by_name(&realm_id, "realm.admin") {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "seed role realm.admin missing"})),
            )
                .into_response();
        }
        Err(e) => return rbac_error_to_response(&e).into_response(),
    };
    if let Err(e) = state.rbac.assign_role(
        &realm_id,
        &AssignRoleRequest {
            subject: Subject::User(user_id.clone()),
            role_id: admin_role.id.clone(),
            scope: Scope::Realm,
            assigned_by: None,
        },
    ) {
        return rbac_error_to_response(&e).into_response();
    }

    // Create session (API-initiated — no browser context)
    let session = match state.identity.create_session(
        &realm_id,
        &user_id,
        &crate::identity::SessionContext::default(),
    ) {
        Ok(s) => s,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    // Issue tokens — now resolves `realm.admin` role's permissions into
    // the JWT claim set.
    let tokens = match state
        .identity
        .issue_tokens(&realm_id, &user_id, session.id())
    {
        Ok(t) => t,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    (
        StatusCode::OK,
        Json(pb::BootstrapResponse {
            realm_id: realm_id.as_uuid().to_string(),
            user_id: user_id.as_uuid().to_string(),
            access_token: tokens.access_token().to_string(),
            refresh_token: tokens.refresh_token().to_string(),
        }),
    )
        .into_response()
}

// =======================================================================
// RBAC admin endpoints (AUTHORIZATION.md § 8.2)
// =======================================================================

#[derive(Debug, Deserialize)]
struct CreateRoleBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    parent_roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateRoleBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<Option<String>>,
    #[serde(default)]
    permissions: Option<Vec<String>>,
    #[serde(default)]
    parent_roles: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CreateGroupBody {
    name: String,
    slug: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateGroupBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    description: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
struct AddGroupMemberBody {
    /// `"user"` or `"group"`.
    #[serde(rename = "type")]
    member_type: String,
    /// UUID of the member entity.
    id: String,
}

#[derive(Debug, Deserialize)]
struct AssignRoleBody {
    role_id: String,
    /// Optional org ID for org-scoped assignments; omit for realm scope.
    #[serde(default)]
    org_id: Option<String>,
}

fn parse_role_id(raw: &str) -> Result<RoleId, (StatusCode, Json<serde_json::Value>)> {
    let stripped = raw.strip_prefix("role_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(RoleId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid role id"})),
            )
        })
}

fn parse_group_id(raw: &str) -> Result<GroupId, (StatusCode, Json<serde_json::Value>)> {
    let stripped = raw.strip_prefix("group_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(GroupId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid group id"})),
            )
        })
}

fn parse_assignment_id(
    raw: &str,
) -> Result<crate::rbac::AssignmentId, (StatusCode, Json<serde_json::Value>)> {
    let stripped = raw.strip_prefix("assign_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(crate::rbac::AssignmentId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid assignment id"})),
            )
        })
}

fn parse_user_id_path(raw: &str) -> Result<UserId, (StatusCode, Json<serde_json::Value>)> {
    let stripped = raw.strip_prefix("user_").unwrap_or(raw);
    uuid::Uuid::parse_str(stripped)
        .map(UserId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user id"})),
            )
        })
}

fn permissions_from_strings(raw: Vec<String>) -> Result<Vec<Permission>, RbacError> {
    raw.into_iter()
        .map(|s| Permission::new(s).map_err(|reason| RbacError::InvalidPermission { reason }))
        .collect()
}

async fn admin_list_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    match state.rbac.list_roles(
        &auth.realm_id,
        pagination.cursor.as_deref(),
        pagination.effective_limit(),
    ) {
        Ok(page) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "items": page.items,
                "next_cursor": page.next_cursor,
            })),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_create_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateRoleBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let permissions = match permissions_from_strings(body.permissions) {
        Ok(p) => p,
        Err(e) => return rbac_error_to_response(&e).into_response(),
    };
    let parent_roles: Result<Vec<RoleId>, _> = body
        .parent_roles
        .into_iter()
        .map(|s| parse_role_id(&s))
        .collect();
    let parent_roles = match parent_roles {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state.rbac.create_role(
        &auth.realm_id,
        &CreateRoleRequest {
            name: body.name,
            description: body.description,
            permissions,
            parent_roles,
            scope_kind: crate::rbac::RoleScopeKind::Realm,
        },
    ) {
        Ok(role) => (StatusCode::CREATED, Json(role)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_get_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let role_id = match parse_role_id(&id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match state.rbac.get_role(&auth.realm_id, &role_id) {
        Ok(Some(role)) => (StatusCode::OK, Json(role)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_update_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateRoleBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let role_id = match parse_role_id(&id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let permissions = match body.permissions {
        Some(raw) => match permissions_from_strings(raw) {
            Ok(p) => Some(p),
            Err(e) => return rbac_error_to_response(&e).into_response(),
        },
        None => None,
    };
    let parent_roles = match body.parent_roles {
        Some(raw) => {
            let parsed: Result<Vec<RoleId>, _> =
                raw.into_iter().map(|s| parse_role_id(&s)).collect();
            match parsed {
                Ok(v) => Some(v),
                Err(e) => return e.into_response(),
            }
        }
        None => None,
    };
    match state.rbac.update_role(
        &auth.realm_id,
        &role_id,
        &UpdateRoleRequest {
            name: body.name,
            description: body.description,
            permissions,
            parent_roles,
            scope_kind: None,
        },
    ) {
        Ok(role) => (StatusCode::OK, Json(role)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_delete_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let role_id = match parse_role_id(&id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    match state.rbac.delete_role(&auth.realm_id, &role_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_list_groups(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    match state.rbac.list_groups(
        &auth.realm_id,
        pagination.cursor.as_deref(),
        pagination.effective_limit(),
    ) {
        Ok(page) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "items": page.items,
                "next_cursor": page.next_cursor,
            })),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateGroupBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    match state.rbac.create_group(
        &auth.realm_id,
        &CreateGroupRequest {
            name: body.name,
            slug: body.slug,
            description: body.description,
        },
    ) {
        Ok(g) => (StatusCode::CREATED, Json(g)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_get_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    match state.rbac.get_group(&auth.realm_id, &group_id) {
        Ok(Some(g)) => (StatusCode::OK, Json(g)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_update_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateGroupBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    match state.rbac.update_group(
        &auth.realm_id,
        &group_id,
        &UpdateGroupRequest {
            name: body.name,
            slug: body.slug,
            description: body.description,
        },
    ) {
        Ok(g) => (StatusCode::OK, Json(g)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_delete_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    match state.rbac.delete_group(&auth.realm_id, &group_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_list_group_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(pagination): Query<PaginationParams>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    match state.rbac.list_group_members(
        &auth.realm_id,
        &group_id,
        pagination.cursor.as_deref(),
        pagination.effective_limit(),
    ) {
        Ok(page) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "items": page.items,
                "next_cursor": page.next_cursor,
            })),
        )
            .into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_add_group_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AddGroupMemberBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let member = match body.member_type.as_str() {
        "user" => match parse_user_id_path(&body.id) {
            Ok(u) => GroupMember::User(u),
            Err(e) => return e.into_response(),
        },
        "group" => match parse_group_id(&body.id) {
            Ok(g) => GroupMember::Group(g),
            Err(e) => return e.into_response(),
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid member type"})),
            )
                .into_response();
        }
    };
    match state
        .rbac
        .add_group_member(&auth.realm_id, &group_id, &member)
    {
        Ok(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_remove_group_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, member_id)): Path<(String, String)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let group_id = match parse_group_id(&id) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let member_type = params.get("type").map_or("user", String::as_str);
    let member = match member_type {
        "user" => match parse_user_id_path(&member_id) {
            Ok(u) => GroupMember::User(u),
            Err(e) => return e.into_response(),
        },
        "group" => match parse_group_id(&member_id) {
            Ok(g) => GroupMember::Group(g),
            Err(e) => return e.into_response(),
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid member type"})),
            )
                .into_response();
        }
    };
    match state
        .rbac
        .remove_group_member(&auth.realm_id, &group_id, &member)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_list_user_assignments(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = match parse_user_id_path(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    match state.rbac.list_user_assignments(&auth.realm_id, &user_id) {
        Ok(items) => (StatusCode::OK, Json(serde_json::json!({"items": items}))).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_assign_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AssignRoleBody>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let user_id = match parse_user_id_path(&id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let role_id = match parse_role_id(&body.role_id) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let scope = match body.org_id {
        Some(s) => {
            let stripped = s.strip_prefix("org_").unwrap_or(&s);
            match uuid::Uuid::parse_str(stripped).map(crate::core::OrganizationId::new) {
                Ok(oid) => Scope::Org { org_id: oid },
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid org id"})),
                    )
                        .into_response();
                }
            }
        }
        None => Scope::Realm,
    };
    match state.rbac.assign_role(
        &auth.realm_id,
        &AssignRoleRequest {
            subject: Subject::User(user_id),
            role_id,
            scope,
            assigned_by: Some(auth.user_id.clone()),
        },
    ) {
        Ok(a) => (StatusCode::CREATED, Json(a)).into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

async fn admin_unassign_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let aid = match parse_assignment_id(&id) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    match state.rbac.unassign_role(&auth.realm_id, &aid) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => rbac_error_to_response(&e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::EmbeddedAuditEngine;
    use crate::core::SystemClock;
    use crate::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
    use crate::rbac::EmbeddedRbacEngine;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use tower::ServiceExt as _;

    /// Creates a test app state with all three engines in a temp directory.
    fn test_state(temp_dir: &std::path::Path) -> Arc<AppState> {
        let config = StorageConfig::dev(temp_dir.to_path_buf());
        let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
        let clock = Arc::new(SystemClock) as Arc<dyn crate::core::Clock>;
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let rbac_engine: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let audit_engine = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_engine = EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&rbac_engine),
            Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
        )
        .expect("identity engine");

        Arc::new(AppState::new(
            Arc::new(identity_engine),
            rbac_engine,
            audit_engine.clone() as Arc<dyn AuditEngine>,
        ))
    }

    /// Creates a test app state in dev mode.
    fn test_state_dev(temp_dir: &std::path::Path) -> Arc<AppState> {
        let config = StorageConfig::dev(temp_dir.to_path_buf());
        let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
        let clock = Arc::new(SystemClock) as Arc<dyn crate::core::Clock>;
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let rbac_engine: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let audit_engine = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_engine = EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&rbac_engine),
            Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
        )
        .expect("identity engine");

        Arc::new(AppState::new_dev(
            Arc::new(identity_engine),
            rbac_engine,
            audit_engine.clone() as Arc<dyn AuditEngine>,
        ))
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let state = test_state(temp_dir.path());
        let app = router(state);

        let resp = axum::serve(TcpListener::bind("127.0.0.1:0").await.expect("bind"), app);
        // Instead of starting the full server, test the handler directly
        drop(resp);
        let result = health().await.into_response();
        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bootstrap_returns_404_in_production_mode() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let state = test_state(temp_dir.path());
        let app = router(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/admin/bootstrap")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn bootstrap_returns_admin_credentials_in_dev_mode() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let state = test_state_dev(temp_dir.path());
        let app = router(state);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/admin/bootstrap")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 10_000)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");

        // Verify all expected fields are present
        assert!(json.get("realm_id").is_some(), "missing realm_id");
        assert!(json.get("user_id").is_some(), "missing user_id");
        assert!(json.get("access_token").is_some(), "missing access_token");
        assert!(json.get("refresh_token").is_some(), "missing refresh_token");

        // Verify realm_id and user_id are valid UUIDs
        let realm_str = json["realm_id"].as_str().expect("realm_id string");
        let _: uuid::Uuid = realm_str.parse().expect("valid realm UUID");
        let user_str = json["user_id"].as_str().expect("user_id string");
        let _: uuid::Uuid = user_str.parse().expect("valid user UUID");

        // Verify access_token is non-empty
        let token = json["access_token"].as_str().expect("access_token string");
        assert!(!token.is_empty(), "access_token should not be empty");
    }
}
