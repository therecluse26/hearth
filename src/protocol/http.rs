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

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::audit::{AuditEngine, CreateAuditEvent};
use crate::authz::{AuthorizationEngine, ObjectRef, SubjectRef};
use crate::core::{ClientId, TenantId, UserId};
use crate::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateTenantRequest, CreateUserRequest,
    IdentityEngine, RegisterClientRequest, TokenExchangeRequest, UpdateClientRequest,
    UpdateTenantRequest, UpdateUserRequest, UserStatus,
};

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

/// Shared application state passed to all route handlers.
pub struct AppState {
    /// The identity engine for all domain operations.
    pub identity: Arc<dyn IdentityEngine>,
    /// The authorization engine for permission checks.
    pub authz: Arc<dyn AuthorizationEngine>,
    /// The audit engine for mutation logging.
    pub audit: Arc<dyn AuditEngine>,
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
        .nest("/admin", admin_routes)
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
    let app = router(state);
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
    let app = router(state);
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
    (StatusCode::OK, Json(doc))
}

/// JWKS endpoint.
///
/// Returns the JSON Web Key Set containing the server's public signing
/// keys for external token verification.
async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let doc = state.identity.jwks();
    (StatusCode::OK, Json(doc))
}

// === User management endpoints ===

/// HTTP request body for user creation.
#[derive(Debug, Deserialize)]
struct HttpCreateUserRequest {
    email: String,
    display_name: String,
}

/// Create a new user.
///
/// Requires `X-Tenant-ID` header. Returns the created user record.
async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpCreateUserRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = CreateUserRequest {
        email: body.email,
        display_name: body.display_name,
    };

    match state.identity.create_user(&tenant_id, &request) {
        Ok(user) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": user.id().as_uuid(),
                "email": user.email(),
                "display_name": user.display_name(),
                "status": format!("{:?}", user.status()),
            })),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === OIDC / OAuth 2.0 endpoints ===

/// HTTP request body for client registration.
#[derive(Debug, Deserialize)]
struct HttpRegisterClientRequest {
    client_name: String,
    redirect_uris: Vec<String>,
}

/// HTTP request body for authorization code flow initiation.
#[derive(Debug, Deserialize)]
struct HttpAuthorizeRequest {
    client_id: ClientId,
    redirect_uri: String,
    scope: String,
    state: String,
    response_type: String,
    user_id: UserId,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

/// HTTP request body for token exchange.
#[derive(Debug, Deserialize)]
struct HttpTokenRequest {
    client_id: ClientId,
    code: String,
    redirect_uri: String,
    code_verifier: Option<String>,
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
        IdentityError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "too many requests"),
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
    Json(body): Json<HttpRegisterClientRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = RegisterClientRequest {
        client_name: body.client_name,
        redirect_uris: body.redirect_uris,
        client_secret: None,
        grant_types: vec!["authorization_code".to_string()],
    };

    match state.identity.register_client(&tenant_id, &request) {
        Ok(client) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(client).unwrap_or_default()),
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
    Json(body): Json<HttpAuthorizeRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let code_challenge_method = match body.code_challenge_method.as_deref() {
        Some("S256") => Some(CodeChallengeMethod::S256),
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "unsupported code_challenge_method"})),
            )
                .into_response();
        }
        None => None,
    };

    let request = AuthorizationRequest {
        client_id: body.client_id,
        redirect_uri: body.redirect_uri,
        scope: body.scope,
        state: body.state,
        response_type: body.response_type,
        user_id: body.user_id,
        code_challenge: body.code_challenge,
        code_challenge_method,
        nonce: body.nonce,
    };

    match state.identity.authorize(&tenant_id, &request) {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "code": response.code(),
                "state": response.state(),
            })),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Exchange an authorization code for tokens.
///
/// Requires `X-Tenant-ID` header. Returns access, ID, and refresh tokens.
async fn token_exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpTokenRequest>,
) -> impl IntoResponse {
    let tenant_id = match extract_tenant_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let request = TokenExchangeRequest {
        client_id: body.client_id,
        code: body.code,
        redirect_uri: body.redirect_uri,
        code_verifier: body.code_verifier,
    };

    match state
        .identity
        .exchange_authorization_code(&tenant_id, &request)
    {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "access_token": response.access_token(),
                "id_token": response.id_token(),
                "token_type": response.token_type(),
                "expires_in": response.expires_in(),
                "refresh_token": response.refresh_token(),
            })),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Admin API endpoints ===

/// Serializes a user to a JSON value for API responses.
fn user_to_json(user: &crate::identity::User) -> serde_json::Value {
    serde_json::json!({
        "id": user.id().as_uuid(),
        "email": user.email(),
        "display_name": user.display_name(),
        "status": format!("{:?}", user.status()),
        "created_at": user.created_at().as_micros(),
        "updated_at": user.updated_at().as_micros(),
    })
}

/// Serializes a tenant to a JSON value for API responses.
fn tenant_to_json(tenant: &crate::identity::Tenant) -> serde_json::Value {
    serde_json::json!({
        "id": tenant.id().as_uuid(),
        "name": tenant.name(),
        "status": format!("{:?}", tenant.status()),
        "config": tenant.config(),
        "created_at": tenant.created_at().as_micros(),
        "updated_at": tenant.updated_at().as_micros(),
    })
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
        &auth.tenant_id,
        params.cursor.as_deref(),
        params.effective_limit(),
    ) {
        Ok(page) => {
            let items: Vec<_> = page.items.iter().map(user_to_json).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "items": items,
                    "next_cursor": page.next_cursor,
                })),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: create user.
async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpCreateUserRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let request = CreateUserRequest {
        email: body.email,
        display_name: body.display_name,
    };

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
            (StatusCode::CREATED, Json(user_to_json(&user))).into_response()
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
        Ok(Some(user)) => (StatusCode::OK, Json(user_to_json(&user))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// HTTP request body for user update (admin).
#[derive(Debug, Deserialize)]
struct HttpUpdateUserRequest {
    email: Option<String>,
    display_name: Option<String>,
    status: Option<String>,
}

/// Admin: update user by ID.
async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<HttpUpdateUserRequest>,
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

    let status = match body.status.as_deref() {
        Some("Active") => Some(UserStatus::Active),
        Some("Disabled") => Some(UserStatus::Disabled),
        Some("PendingVerification") => Some(UserStatus::PendingVerification),
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid status"})),
            )
                .into_response()
        }
        None => None,
    };

    let request = UpdateUserRequest {
        email: body.email,
        display_name: body.display_name,
        status,
    };
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
            (StatusCode::OK, Json(user_to_json(&user))).into_response()
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
    users: Vec<HttpCreateUserRequest>,
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
            let requests: Vec<CreateUserRequest> = body
                .users
                .iter()
                .map(|u| CreateUserRequest {
                    email: u.email.clone(),
                    display_name: u.display_name.clone(),
                })
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

                    let json_results: Vec<_> = results
                        .iter()
                        .map(|r| match &r.result {
                            Ok(user) => serde_json::json!({
                                "index": r.index,
                                "success": true,
                                "user": user_to_json(user),
                            }),
                            Err(err) => serde_json::json!({
                                "index": r.index,
                                "success": false,
                                "error": err,
                            }),
                        })
                        .collect();

                    (
                        StatusCode::OK,
                        Json(serde_json::json!({"results": json_results})),
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

                    let json_results: Vec<_> = results
                        .iter()
                        .map(|r| match &r.result {
                            Ok(()) => serde_json::json!({
                                "index": r.index,
                                "success": true,
                            }),
                            Err(err) => serde_json::json!({
                                "index": r.index,
                                "success": false,
                                "error": err,
                            }),
                        })
                        .collect();

                    (
                        StatusCode::OK,
                        Json(serde_json::json!({"results": json_results})),
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
        Ok(page) => {
            let items: Vec<_> = page.items.iter().map(tenant_to_json).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "items": items,
                    "next_cursor": page.next_cursor,
                })),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// HTTP request body for tenant creation.
#[derive(Debug, Deserialize)]
struct HttpCreateTenantRequest {
    name: String,
    config: Option<crate::identity::TenantConfig>,
}

/// Admin: create tenant.
async fn admin_create_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpCreateTenantRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let request = CreateTenantRequest {
        name: body.name,
        config: body.config,
    };

    match state.identity.create_tenant(&request) {
        Ok(tenant) => {
            let _ = state.audit.append(&CreateAuditEvent {
                tenant_id: auth.tenant_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::TenantCreated,
                resource_type: "tenant".to_string(),
                resource_id: tenant.id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (StatusCode::CREATED, Json(tenant_to_json(&tenant))).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
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
        Ok(Some(tenant)) => (StatusCode::OK, Json(tenant_to_json(&tenant))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// HTTP request body for tenant update.
#[derive(Debug, Deserialize)]
struct HttpUpdateTenantRequest {
    name: Option<String>,
    status: Option<String>,
    config: Option<crate::identity::TenantConfig>,
}

/// Admin: update tenant by ID.
async fn admin_update_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<HttpUpdateTenantRequest>,
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

    let status = match body.status.as_deref() {
        Some("Active") => Some(crate::identity::TenantStatus::Active),
        Some("Suspended") => Some(crate::identity::TenantStatus::Suspended),
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid status"})),
            )
                .into_response()
        }
        None => None,
    };

    let tid = TenantId::new(tenant_uuid);
    let request = UpdateTenantRequest {
        name: body.name,
        status,
        config: body.config,
    };

    match state.identity.update_tenant(&tid, &request) {
        Ok(tenant) => {
            let _ = state.audit.append(&CreateAuditEvent {
                tenant_id: auth.tenant_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::TenantUpdated,
                resource_type: "tenant".to_string(),
                resource_id: tenant_uuid.to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            });
            (StatusCode::OK, Json(tenant_to_json(&tenant))).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: delete tenant by ID.
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

    match state.identity.delete_tenant(&TenantId::new(tenant_uuid)) {
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
        Ok(page) => {
            let items: Vec<_> = page
                .items
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "client_id": c.client_id().as_uuid(),
                        "client_name": c.client_name(),
                        "redirect_uris": c.redirect_uris(),
                        "created_at": c.created_at().as_micros(),
                        "grant_types": c.grant_types(),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "items": items,
                    "next_cursor": page.next_cursor,
                })),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Admin: register a new client.
async fn admin_register_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpRegisterClientRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let request = RegisterClientRequest {
        client_name: body.client_name,
        redirect_uris: body.redirect_uris,
        client_secret: None,
        grant_types: vec!["authorization_code".to_string()],
    };

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
                Json(serde_json::to_value(client).unwrap_or_default()),
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
            Json(serde_json::to_value(client).unwrap_or_default()),
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

/// HTTP request body for client update.
#[derive(Debug, Deserialize)]
struct HttpUpdateClientRequest {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
}

/// Admin: update client by ID.
async fn admin_update_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<HttpUpdateClientRequest>,
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

    let request = UpdateClientRequest {
        client_name: body.client_name,
        redirect_uris: body.redirect_uris,
    };

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
                Json(serde_json::to_value(client).unwrap_or_default()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::EmbeddedAuditEngine;
    use crate::authz::{AuthzConfig, EmbeddedAuthzEngine};
    use crate::core::SystemClock;
    use crate::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

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
}
