//! HTTP server and route definitions.
//!
//! Builds an [`axum::Router`] with health, OIDC discovery, JWKS, OAuth 2.0,
//! and Admin API endpoints. The server is configured with shared application
//! state containing the identity, authorization, and audit engines.
//!
//! The protocol layer is a thin, stateless adapter: it translates HTTP requests
//! into domain calls on `IdentityEngine` and maps `IdentityError` to HTTP
//! status codes. No business logic lives here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::audit::{AuditEngine, CreateAuditEvent};
use crate::authz::{AuthorizationEngine, ObjectRef, RelationshipTuple, SubjectRef, TupleWrite};
use crate::core::{ClientId, TenantId, UserId};
use crate::identity::IdentityEngine;
use crate::protocol::convert::identity::{
    proto_user_status_to_domain, tenant_page_to_proto, user_bulk_result_to_proto,
    user_page_to_proto, void_bulk_result_to_proto,
};
use crate::protocol::convert::oauth::{
    client_page_to_proto, proto_authorize_to_domain, proto_client_creds_to_domain,
    proto_token_exchange_to_domain,
};
use crate::protocol::proto::identity::v1 as pb;

/// Tracks admin API rate limiting per user.
#[derive(Debug, Clone)]
struct AdminRateTracker {
    /// Number of requests in the current window.
    count: u32,
    /// Start of the current window (Unix microseconds).
    window_start_micros: i64,
}

/// Maximum admin API requests per minute per user.
const ADMIN_RATE_LIMIT: u32 = 100;
/// Rate limit window in microseconds (1 minute).
const ADMIN_RATE_WINDOW_MICROS: i64 = 60 * 1_000_000;

/// Default maximum request body size (1 MiB).
///
/// Covers normal JSON payloads (user/tenant CRUD, OAuth token exchange).
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
    /// The authorization engine for permission checks.
    pub authz: Arc<dyn AuthorizationEngine>,
    /// The audit engine for mutation logging.
    pub audit: Arc<dyn AuditEngine>,
    /// Whether the server is running in development mode.
    ///
    /// Enables the `POST /admin/bootstrap` endpoint for SDK integration
    /// tests and local development.
    pub dev_mode: bool,
    /// Per-admin-user rate trackers. Key: user UUID string.
    admin_rate_trackers: Mutex<HashMap<String, AdminRateTracker>>,
}

impl AppState {
    /// Creates a new `AppState` with all three engines.
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        authz: Arc<dyn AuthorizationEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        Self {
            identity,
            authz,
            audit,
            dev_mode: false,
            admin_rate_trackers: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a new `AppState` in development mode.
    ///
    /// Enables the `POST /admin/bootstrap` endpoint.
    pub fn new_dev(
        identity: Arc<dyn IdentityEngine>,
        authz: Arc<dyn AuthorizationEngine>,
        audit: Arc<dyn AuditEngine>,
    ) -> Self {
        Self {
            identity,
            authz,
            audit,
            dev_mode: true,
            admin_rate_trackers: Mutex::new(HashMap::new()),
        }
    }
}

/// Authenticated admin context extracted from request headers.
///
/// Contains the tenant and user that passed both token validation
/// and Zanzibar admin role check.
#[derive(Debug, Clone)]
struct AdminAuth {
    tenant_id: TenantId,
    user_id: UserId,
}

/// Extracts and validates admin authentication from request headers.
///
/// 1. Extracts `Authorization: Bearer <token>` and `X-Tenant-ID`
/// 2. Validates the token via `identity.validate_token()`
/// 3. Checks admin role via `authz.check(hearth#admin@user:uuid)`
/// 4. Checks rate limit (100 req/min per admin user)
fn extract_admin_auth(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AdminAuth, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = extract_tenant_id(headers)?;

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
        .validate_token(&tenant_id, token)
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

    // Check admin role via Zanzibar
    // INVARIANT: "hearth"/"admin"/"user" are valid ObjectRef fields (short ASCII strings)
    #[allow(clippy::unwrap_used)]
    let object = ObjectRef::new("hearth", "admin").unwrap();
    #[allow(clippy::unwrap_used)]
    let subject = SubjectRef::direct("user", &user_id.as_uuid().to_string()).unwrap();
    let is_admin = state
        .authz
        .check(&tenant_id, &object, "admin", &subject, None)
        .unwrap_or(false);

    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        ));
    }

    // Rate limiting
    check_admin_rate_limit(state, &user_id)?;

    Ok(AdminAuth { tenant_id, user_id })
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

    let key = user_id.as_uuid().to_string();
    let mut trackers = state
        .admin_rate_trackers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let tracker = trackers.entry(key).or_insert(AdminRateTracker {
        count: 0,
        window_start_micros: now,
    });

    // Reset window if expired
    if now - tracker.window_start_micros > ADMIN_RATE_WINDOW_MICROS {
        tracker.count = 0;
        tracker.window_start_micros = now;
    }

    tracker.count += 1;
    if tracker.count > ADMIN_RATE_LIMIT {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "rate limit exceeded"})),
        ));
    }

    Ok(())
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
            "/tenants",
            axum::routing::get(admin_list_tenants).post(admin_create_tenant),
        )
        .route(
            "/tenants/{id}",
            axum::routing::get(admin_get_tenant)
                .put(admin_update_tenant)
                .delete(admin_delete_tenant),
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
        .route("/audit", axum::routing::get(admin_list_audit));

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
        .route("/register", axum::routing::post(dynamic_register_client))
        .nest("/admin", admin_routes)
        .route("/admin/bootstrap", axum::routing::post(admin_bootstrap))
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

    axum::serve(listener, app)
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
/// Requires `X-Tenant-ID` header. Returns the created user record.
async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::CreateUserRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::CreateUserRequest::from(body);

    match state.identity.create_user(&tenant_id, &request) {
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

/// Extracts a `TenantId` from the `X-Tenant-ID` header.
///
/// Returns a `(StatusCode, Json)` error if the header is missing or invalid.
fn extract_tenant_id(
    headers: &HeaderMap,
) -> Result<TenantId, (StatusCode, Json<serde_json::Value>)> {
    let header_value = headers
        .get("x-tenant-id")
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing X-Tenant-ID header"})),
            )
        })?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid X-Tenant-ID header"})),
            )
        })?;

    let uuid: uuid::Uuid = header_value.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "X-Tenant-ID must be a valid UUID"})),
        )
    })?;

    Ok(TenantId::new(uuid))
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
        IdentityError::TenantNotFound | IdentityError::UserNotFound => {
            (StatusCode::NOT_FOUND, "not found")
        }
        IdentityError::TenantSuspended => (StatusCode::FORBIDDEN, "tenant suspended"),
        IdentityError::DuplicateTenantName => (StatusCode::CONFLICT, "duplicate tenant name"),
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
        IdentityError::SigningError { .. }
        | IdentityError::Storage(_)
        | IdentityError::Serialization { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    };

    (status, Json(serde_json::json!({"error": message})))
}

/// Register an OAuth 2.0 client.
///
/// Requires `X-Tenant-ID` header. Returns the created client record.
async fn register_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::RegisterClientRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;

    match state.identity.register_client(&tenant_id, &request) {
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
/// Requires `X-Tenant-ID` header. Returns an authorization code and state.
async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::AuthorizationRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
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

    match state.identity.authorize(&tenant_id, &request) {
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
/// Requires `X-Tenant-ID` header.
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
    let tenant_id = match extract_tenant_id(&headers) {
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
                .exchange_authorization_code(&tenant_id, &request)
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

            match state.identity.refresh_tokens(&tenant_id, &refresh_token) {
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

            match state
                .identity
                .client_credentials_token(&tenant_id, &request)
            {
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
                .poll_device_token(&tenant_id, &device_code, &client_id)
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
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::TokenRevocationRequest::from(body);

    match state.identity.revoke_token(&tenant_id, &request) {
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
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::TokenIntrospectionRequest::from(body);

    match state.identity.introspect_token(&tenant_id, &request) {
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
    let tenant_id = match extract_tenant_id(&headers) {
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

    match state.identity.device_authorize(&tenant_id, &request) {
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
    let tenant_id = match extract_tenant_id(&headers) {
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

    match state.identity.userinfo(&tenant_id, token) {
        Ok(info) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::UserInfoResponse::from(&info))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Dynamic Client Registration (RFC 7591) ===

/// POST /register — dynamically register a new OAuth 2.0 client.
/// Request body for dynamic client registration (RFC 7591).
///
/// Uses a custom struct because RFC 7591 fields are all optional.
#[derive(Debug, Deserialize)]
struct HttpDynamicRegisterRequest {
    /// Human-readable client name.
    client_name: Option<String>,
    /// Redirect URIs for the client.
    redirect_uris: Option<Vec<String>>,
    /// Grant types the client will use.
    grant_types: Option<Vec<String>>,
}

async fn dynamic_register_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpDynamicRegisterRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = crate::identity::RegisterClientRequest {
        client_name: body.client_name.unwrap_or_default(),
        redirect_uris: body.redirect_uris.unwrap_or_default(),
        client_secret: None, // Dynamic registration creates public clients
        grant_types: body
            .grant_types
            .unwrap_or_else(|| vec!["authorization_code".to_string()]),
    };

    match state.identity.register_client(&tenant_id, &request) {
        Ok(client) => {
            // RFC 7591 response includes registration_client_uri, not in proto
            let mut resp = proto_to_rest_json(&pb::OAuthClient::from(&client));
            if let Some(obj) = resp.as_object_mut() {
                obj.insert(
                    "registration_client_uri".to_string(),
                    serde_json::Value::String(format!(
                        "/register/{}",
                        client.client_id().as_uuid()
                    )),
                );
            }
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Admin API endpoints ===

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
        &auth.tenant_id,
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

    match state.identity.create_user(&auth.tenant_id, &request) {
        Ok(user) => {
            let _ = state.audit.append(&CreateAuditEvent {
                tenant_id: auth.tenant_id.clone(),
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
        .get_user(&auth.tenant_id, &UserId::new(user_uuid))
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

    match state.identity.update_user(&auth.tenant_id, &uid, &request) {
        Ok(user) => {
            let _ = state.audit.append(&CreateAuditEvent {
                tenant_id: auth.tenant_id.clone(),
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
        .delete_user(&auth.tenant_id, &UserId::new(user_uuid))
    {
        Ok(()) => {
            let _ = state.audit.append(&CreateAuditEvent {
                tenant_id: auth.tenant_id.clone(),
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

            match state.identity.bulk_create_users(&auth.tenant_id, &requests) {
                Ok(results) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        tenant_id: auth.tenant_id.clone(),
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

            match state
                .identity
                .bulk_disable_users(&auth.tenant_id, &user_ids)
            {
                Ok(results) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        tenant_id: auth.tenant_id.clone(),
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

/// Admin: list tenants (paginated).
async fn admin_list_tenants(
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
        .list_tenants(params.cursor.as_deref(), params.effective_limit())
    {
        Ok(page) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&tenant_page_to_proto(&page))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: create tenant — disabled; tenants are managed via `hearth.yaml`.
async fn admin_create_tenant() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "error": "method_not_allowed",
            "message": "Tenants are managed via hearth.yaml. Remove this endpoint from your client."
        })),
    )
}

/// Admin: get tenant by ID.
async fn admin_get_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let tenant_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid tenant ID"})),
            )
                .into_response()
        }
    };

    match state.identity.get_tenant(&TenantId::new(tenant_uuid)) {
        Ok(Some(tenant)) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::Tenant::from(&tenant))),
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

/// Admin: update tenant — disabled; tenants are managed via `hearth.yaml`.
async fn admin_update_tenant(Path(_id): Path<String>) -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "error": "method_not_allowed",
            "message": "Tenants are managed via hearth.yaml. Remove this endpoint from your client."
        })),
    )
}

/// Admin: delete tenant by ID.
///
/// Only allows permanent deletion of tenants with `Archived` status.
/// Active or Suspended tenants must first be removed from `hearth.yaml`
/// and the server restarted (which archives them via reconciliation).
async fn admin_delete_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let tenant_uuid: uuid::Uuid = match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid tenant ID"})),
            )
                .into_response()
        }
    };

    let tid = TenantId::new(tenant_uuid);

    // Check tenant status — only Archived tenants can be permanently deleted.
    match state.identity.get_tenant(&tid) {
        Ok(Some(tenant))
            if tenant.status() == crate::identity::TenantStatus::Archived =>
        {
            match state.identity.delete_tenant(&tid) {
                Ok(()) => {
                    let _ = state.audit.append(&CreateAuditEvent {
                        tenant_id: auth.tenant_id.clone(),
                        actor: auth.user_id.as_uuid().to_string(),
                        action: crate::audit::AuditAction::TenantDeleted,
                        resource_type: "tenant".to_string(),
                        resource_id: tenant_uuid.to_string(),
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
                "message": "Only archived tenants can be permanently deleted. Remove the tenant from hearth.yaml and restart to archive it first."
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
        &auth.tenant_id,
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

    match state.identity.register_client(&auth.tenant_id, &request) {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                tenant_id: auth.tenant_id.clone(),
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
        .get_client(&auth.tenant_id, &ClientId::new(client_uuid))
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
        .update_client(&auth.tenant_id, &ClientId::new(client_uuid), &request)
    {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                tenant_id: auth.tenant_id.clone(),
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
        .delete_client(&auth.tenant_id, &ClientId::new(client_uuid))
    {
        Ok(()) => {
            let _ = state.audit.append(&CreateAuditEvent {
                tenant_id: auth.tenant_id.clone(),
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
        tenant_id: auth.tenant_id.clone(),
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

// === Dev Bootstrap Endpoint ===

/// POST /admin/bootstrap — creates a tenant, admin user, session, Zanzibar
/// admin tuple, and issues tokens. Returns everything needed for SDK tests.
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

    // Create tenant
    let tenant = match state
        .identity
        .create_tenant(&crate::identity::CreateTenantRequest {
            name: "dev-tenant".to_string(),
            config: None,
        }) {
        Ok(t) => t,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let tenant_id = tenant.id().clone();

    // Create admin user
    let user = match state.identity.create_user(
        &tenant_id,
        &crate::identity::CreateUserRequest {
            email: "admin@dev.local".to_string(),
            display_name: "Dev Admin".to_string(),
        },
    ) {
        Ok(u) => u,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let user_id = user.id().clone();

    // Create session
    let session = match state.identity.create_session(&tenant_id, &user_id) {
        Ok(s) => s,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    // Issue tokens
    let tokens = match state
        .identity
        .issue_tokens(&tenant_id, &user_id, session.id())
    {
        Ok(t) => t,
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    // Write Zanzibar admin tuple: hearth#admin@user:<uuid>
    // INVARIANT: "hearth", "admin", "user" are valid field names (short ASCII)
    #[allow(clippy::unwrap_used)]
    let object = ObjectRef::new("hearth", "admin").unwrap();
    #[allow(clippy::unwrap_used)]
    let subject = SubjectRef::direct("user", &user_id.as_uuid().to_string()).unwrap();
    #[allow(clippy::unwrap_used)]
    let tuple = RelationshipTuple::new(object, "admin", subject).unwrap();

    if let Err(e) = state
        .authz
        .write_tuples(&tenant_id, &[TupleWrite::Touch(tuple)])
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to write admin tuple: {e}")})),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(pb::BootstrapResponse {
            tenant_id: tenant_id.as_uuid().to_string(),
            user_id: user_id.as_uuid().to_string(),
            access_token: tokens.access_token().to_string(),
            refresh_token: tokens.refresh_token().to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::EmbeddedAuditEngine;
    use crate::authz::{AuthzConfig, EmbeddedAuthzEngine};
    use crate::core::SystemClock;
    use crate::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
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
        let identity_engine = EmbeddedIdentityEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
        )
        .expect("identity engine");
        let authz_engine = EmbeddedAuthzEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            AuthzConfig::default(),
        );
        let audit_engine =
            EmbeddedAuditEngine::new(Arc::clone(&engine) as Arc<dyn StorageEngine>, clock);

        Arc::new(AppState::new(
            Arc::new(identity_engine),
            Arc::new(authz_engine),
            Arc::new(audit_engine),
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
        let identity_engine = EmbeddedIdentityEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
        )
        .expect("identity engine");
        let authz_engine = EmbeddedAuthzEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            AuthzConfig::default(),
        );
        let audit_engine =
            EmbeddedAuditEngine::new(Arc::clone(&engine) as Arc<dyn StorageEngine>, clock);

        Arc::new(AppState::new_dev(
            Arc::new(identity_engine),
            Arc::new(authz_engine),
            Arc::new(audit_engine),
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
        assert!(json.get("tenant_id").is_some(), "missing tenant_id");
        assert!(json.get("user_id").is_some(), "missing user_id");
        assert!(json.get("access_token").is_some(), "missing access_token");
        assert!(json.get("refresh_token").is_some(), "missing refresh_token");

        // Verify tenant_id and user_id are valid UUIDs
        let tenant_str = json["tenant_id"].as_str().expect("tenant_id string");
        let _: uuid::Uuid = tenant_str.parse().expect("valid tenant UUID");
        let user_str = json["user_id"].as_str().expect("user_id string");
        let _: uuid::Uuid = user_str.parse().expect("valid user UUID");

        // Verify access_token is non-empty
        let token = json["access_token"].as_str().expect("access_token string");
        assert!(!token.is_empty(), "access_token should not be empty");
    }
}
