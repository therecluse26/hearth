//! HTTP server and route definitions.
//!
//! Builds an [`axum::Router`] with health, OIDC discovery, JWKS, OAuth 2.0,
//! and Admin API endpoints. The server is configured with shared application
//! state containing the identity, RBAC, and audit engines.
//!
//! The protocol layer is a thin, stateless adapter: it translates HTTP requests
//! into domain calls on `IdentityEngine` and maps `IdentityError` to HTTP
//! status codes. No business logic lives here.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{DefaultBodyLimit, MatchedPath, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Redirect;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::{debug, error, info, Level};

use crate::audit::{AuditEngine, CreateAuditEvent};
use crate::core::{ClientId, RealmId, UserId, WebhookId};
use crate::identity::email::{validate_email_template, EmailBranding, LocalizedEmailTemplate};
use crate::identity::{IdentityEngine, PasswordGrantRequest, UpdateRealmRequest};
use crate::protocol::admin_auth::{
    AdminRateLimiter, RateLimitOutcome, TokenRateLimitOutcome, TokenRateLimiter,
};
use crate::protocol::client_info::extract_client_ip;
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
use crate::webhook::{
    CreateWebhookRequest, DeliveryQuery, UpdateWebhookRequest, WebhookEngine, WebhookQuery,
};

/// Fallback peer address when `ConnectInfo` is unavailable (e.g. test
/// harnesses that use `tower::oneshot` without connect-info). Results in
/// per-IP rate limiting being a no-op (empty-string IP) when no trusted
/// proxies are configured, matching the web-handler pattern.
const FALLBACK_PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

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
    /// Webhook subscription and delivery engine (optional; absent in test
    /// harnesses that don't configure outbound delivery).
    pub webhook: Option<Arc<dyn WebhookEngine>>,
    /// Whether the server is running in development mode.
    ///
    /// Enables the `POST /admin/bootstrap` endpoint for SDK integration
    /// tests and local development.
    pub dev_mode: bool,
    /// Whether the `/metrics` Prometheus scrape endpoint is enabled.
    ///
    /// Controlled by `metrics.enabled` in `hearth.yaml` (default: `true`).
    pub metrics_enabled: bool,
    /// Shared admin API rate limiter. Shared between the HTTP and gRPC
    /// admin surfaces so a caller cannot evade the limit by switching
    /// protocols.
    pub admin_rate_limiter: Arc<AdminRateLimiter>,
    /// Per-`(realm, client_id)` rate limiter for token, introspection, and
    /// device-authorization endpoints. Returns 429 with `Retry-After` when
    /// exceeded.
    pub token_rate_limiter: Arc<TokenRateLimiter>,
    /// Grace period (seconds) during which a retiring signing key remains in
    /// JWKS after rotation. Sourced from `token.signing_key_rotation_grace_period`.
    pub signing_key_rotation_grace_period_secs: u64,
    /// Trusted reverse-proxy IPs for `X-Forwarded-For` extraction.
    ///
    /// When non-empty, the OWASP "rightmost non-trusted" algorithm is applied
    /// to derive the real client IP. When empty (default), the peer socket
    /// IP is used directly.
    pub trusted_proxies: Vec<IpAddr>,
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
            webhook: None,
            dev_mode: false,
            metrics_enabled: true,
            admin_rate_limiter: Arc::new(AdminRateLimiter::new()),
            token_rate_limiter: Arc::new(TokenRateLimiter::new()),
            signing_key_rotation_grace_period_secs: 86_400,
            trusted_proxies: Vec::new(),
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
            webhook: None,
            dev_mode: true,
            metrics_enabled: true,
            admin_rate_limiter: Arc::new(AdminRateLimiter::new()),
            token_rate_limiter: Arc::new(TokenRateLimiter::new()),
            signing_key_rotation_grace_period_secs: 86_400,
            trusted_proxies: Vec::new(),
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
            webhook: None,
            dev_mode: false,
            metrics_enabled: true,
            admin_rate_limiter,
            token_rate_limiter: Arc::new(TokenRateLimiter::new()),
            signing_key_rotation_grace_period_secs: 86_400,
            trusted_proxies: Vec::new(),
        }
    }

    /// Configures trusted reverse-proxy IPs for `X-Forwarded-For` extraction.
    pub fn with_trusted_proxies(mut self, proxies: Vec<IpAddr>) -> Self {
        self.trusted_proxies = proxies;
        self
    }

    /// Attaches a webhook engine, enabling the webhook management endpoints.
    pub fn with_webhook(mut self, webhook: Arc<dyn WebhookEngine>) -> Self {
        self.webhook = Some(webhook);
        self
    }

    /// Sets whether the `/metrics` Prometheus scrape endpoint is exposed.
    pub fn with_metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    /// Sets the signing key rotation grace period.
    pub fn with_signing_key_rotation_grace_period_secs(mut self, secs: u64) -> Self {
        self.signing_key_rotation_grace_period_secs = secs;
        self
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
    // Design decision: a single `hearth.admin` gate is intentional — all admin
    // endpoints share the same all-or-nothing permission. Granular sub-scopes
    // (e.g. `hearth.admin.users:read`) are not required by the current spec and
    // would require changes to token issuance, RBAC seeding, and every handler.
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

/// Checks the per-`(realm, client)` token endpoint rate limit.
///
/// Returns `Ok(())` when the request is allowed; `Err(Response)` with
/// `429 Too Many Requests` and a `Retry-After` header when exceeded.
fn check_token_rate_limit(
    state: &AppState,
    realm_id: &RealmId,
    client_id: &ClientId,
) -> Result<(), Response> {
    #[allow(clippy::cast_possible_truncation)]
    let now_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;

    match state
        .token_rate_limiter
        .check(realm_id, client_id, now_micros)
    {
        TokenRateLimitOutcome::Allowed => Ok(()),
        TokenRateLimitOutcome::Exceeded { retry_after_secs } => {
            let retry_str = retry_after_secs.to_string();
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_str.as_str())],
                Json(serde_json::json!({
                    "error": "too_many_requests",
                    "error_description": "rate limit exceeded"
                })),
            )
                .into_response())
        }
    }
}

/// Builds a 429 Too Many Requests response with a `Retry-After` header.
///
/// Used for per-IP login rate limits on the token and magic-link endpoints.
fn make_ip_rate_limit_response(retry_after_secs: u32) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(
            axum::http::header::RETRY_AFTER,
            retry_after_secs.to_string(),
        )],
        Json(serde_json::json!({
            "error": "too_many_requests",
            "error_description": "rate limit exceeded"
        })),
    )
        .into_response()
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
        .route("/users/import", axum::routing::post(admin_import_users))
        .route("/users/export", axum::routing::get(admin_export_users))
        .route(
            "/users/{id}",
            axum::routing::get(admin_get_user)
                .patch(admin_update_user)
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
            "/realms/{id}/rotate-signing-key",
            axum::routing::post(admin_rotate_realm_signing_key),
        )
        .route(
            "/realms/{id}/branding",
            axum::routing::get(admin_get_realm_branding).patch(admin_patch_realm_branding),
        )
        .route(
            "/realms/{id}/email-templates",
            axum::routing::get(admin_list_realm_email_templates),
        )
        .route(
            "/realms/{id}/email-templates/{kind}",
            axum::routing::get(admin_get_realm_email_template)
                .put(admin_put_realm_email_template)
                .delete(admin_delete_realm_email_template),
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
        .route(
            "/users/{id}/effective-permissions",
            axum::routing::get(admin_get_user_effective_permissions),
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
        )
        .route(
            "/webhooks",
            axum::routing::get(admin_list_webhooks).post(admin_create_webhook),
        )
        .route(
            "/webhooks/{id}",
            axum::routing::get(admin_get_webhook)
                .put(admin_update_webhook)
                .delete(admin_delete_webhook),
        )
        .route(
            "/webhooks/{id}/deliveries",
            axum::routing::get(admin_list_webhook_deliveries),
        );

    Router::new()
        .route("/health", axum::routing::get(health))
        .route("/healthz", axum::routing::get(healthz))
        .route("/readyz", axum::routing::get(readyz))
        .route("/metrics", axum::routing::get(metrics_handler))
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(oidc_discovery),
        )
        .route("/jwks", axum::routing::get(jwks))
        .route("/certs", axum::routing::get(jwks))
        .route("/.well-known/jwks.json", axum::routing::get(jwks))
        .route("/users", axum::routing::post(create_user))
        .route("/clients", axum::routing::post(register_client))
        .route(
            "/register",
            axum::routing::post(register_client_dynamic)
                .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
        )
        .route("/authorize", axum::routing::post(authorize))
        .route(
            "/token",
            axum::routing::post(token_exchange).options(token_preflight),
        )
        .route(
            "/end_session",
            axum::routing::get(end_session).post(end_session),
        )
        .route(
            "/revoke",
            axum::routing::post(token_revocation)
                .options(token_preflight)
                .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
        )
        .route(
            "/introspect",
            axum::routing::post(token_introspection)
                .options(token_preflight)
                .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
        )
        .route(
            "/device_authorization",
            axum::routing::post(device_authorization).options(token_preflight),
        )
        .route("/userinfo", axum::routing::get(userinfo))
        .route("/v1/me/permissions", axum::routing::get(me_permissions))
        .route(
            "/v1/{realm}/auth/magic-link",
            axum::routing::post(magic_link_request)
                .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
        )
        .route("/oauth/consents", axum::routing::get(self_list_consents))
        .route(
            "/oauth/consents/{client_id}",
            axum::routing::delete(self_revoke_consent),
        )
        .route(
            "/webauthn/register/begin",
            axum::routing::post(webauthn_register_begin),
        )
        .route(
            "/webauthn/register/complete",
            axum::routing::post(webauthn_register_complete),
        )
        .route(
            "/webauthn/auth/begin",
            axum::routing::post(webauthn_auth_begin),
        )
        .route(
            "/webauthn/auth/complete",
            axum::routing::post(webauthn_auth_complete),
        )
        .route(
            "/webauthn/credentials",
            axum::routing::get(webauthn_list_credentials),
        )
        .route(
            "/webauthn/credentials/{credential_id}",
            axum::routing::delete(webauthn_delete_credential),
        )
        .nest("/admin", admin_routes)
        .route("/admin/bootstrap", axum::routing::post(admin_bootstrap))
        .nest("/scim/v2", crate::protocol::scim::router())
        .nest(
            "/realms/{realm_name}",
            Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    axum::routing::get(realm_oidc_discovery),
                )
                .route("/.well-known/jwks.json", axum::routing::get(realm_jwks))
                .route("/authorize", axum::routing::post(realm_authorize))
                .route(
                    "/token",
                    axum::routing::post(realm_token_exchange).options(realm_token_preflight),
                )
                .route(
                    "/revoke",
                    axum::routing::post(realm_token_revocation)
                        .options(realm_token_preflight)
                        .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
                )
                .route(
                    "/introspect",
                    axum::routing::post(realm_token_introspection)
                        .options(realm_token_preflight)
                        .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
                )
                .route(
                    "/device_authorization",
                    axum::routing::post(realm_device_authorization).options(realm_token_preflight),
                )
                .route("/userinfo", axum::routing::get(realm_userinfo))
                .route(
                    "/register",
                    axum::routing::post(realm_register_client_dynamic)
                        .route_layer(DefaultBodyLimit::max(BODY_LIMIT_SMALL)),
                ),
        )
        .route_layer(axum::middleware::from_fn(track_metrics))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .level(Level::INFO)
                        .include_headers(false),
                )
                .on_response(DefaultOnResponse::new().level(Level::DEBUG)),
        )
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
/// Accepts connections on the given pre-bound `listener` and responds to every
/// request with a `301 Moved Permanently` redirect to the HTTPS equivalent URL
/// on the given `https_port`.
///
/// The caller is responsible for binding the listener; this function does not
/// call `bind()` internally so callers can detect the assigned port before
/// invoking this function.
pub async fn serve_redirect(
    listener: TcpListener,
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

// === Observability middleware ===

/// Tower middleware that records HTTP request latency into the Prometheus
/// `hearth_http_request_duration_seconds` histogram.
///
/// Must be applied via [`Router::route_layer`] so that [`MatchedPath`] is
/// already populated by the router before this middleware runs. Routes without
/// a matched pattern (e.g. 404s) fall back to the raw URI path.
pub(crate) async fn track_metrics(request: Request, next: Next) -> Response {
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned());
    let method = request.method().as_str().to_owned();

    let start = Instant::now();
    let response = next.run(request).await;
    let elapsed = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();
    crate::metrics::metrics()
        .http_request_duration_seconds
        .with_label_values(&[&method, &path, &status])
        .observe(elapsed);

    response
}

// === Route handlers ===

/// Liveness probe endpoint.
///
/// Returns `200 OK` immediately — if the process can serve HTTP it is alive.
/// Kubernetes uses this to decide when to restart a crashed or deadlocked pod.
/// Unlike `/readyz`, this endpoint does **not** check external dependencies.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// Readiness probe endpoint.
///
/// Returns `200 OK` when the storage engine is accessible and the server is
/// prepared to handle traffic. Returns `503 Service Unavailable` when the
/// storage layer is unreachable (e.g. during startup or after a corruption
/// event). Kubernetes gates inbound traffic behind this check.
async fn readyz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let identity = Arc::clone(&state.identity);
    let healthy = tokio::task::spawn_blocking(move || identity.is_storage_healthy())
        .await
        .unwrap_or(false);

    if healthy {
        (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ready", "storage": "ok"})),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "storage": "unavailable"})),
        )
    }
}

/// Prometheus metrics scrape endpoint (`/metrics`).
///
/// Returns the current metric snapshot in the Prometheus text exposition
/// format (version 0.0.4). Operators should point their Prometheus scrape
/// config at this path.
///
/// No authentication is required by default — operators SHOULD firewall this
/// endpoint from the public internet if the metric cardinality reveals
/// sensitive business data (e.g. realm names in label sets).
async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if !state.metrics_enabled {
        return (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            String::new(),
        )
            .into_response();
    }
    let body = crate::metrics::metrics().render();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// Health check endpoint.
///
/// Returns 200 OK with a JSON body indicating the server is healthy.
/// Used by load balancers, monitoring, and CLI integration tests.
///
/// Prefer `/healthz` (liveness) or `/readyz` (readiness) for Kubernetes probes.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// OIDC Discovery endpoint.
///
/// Returns the `OpenID` Connect Discovery 1.0 document describing the
/// provider's configuration, endpoints, and supported features.
async fn oidc_discovery(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Serialize the domain type directly so optional fields like
    // end_session_endpoint are included without proto schema changes.
    let doc = state.identity.oidc_discovery();
    (StatusCode::OK, Json(doc))
}

/// JWKS endpoint (`/jwks`, `/certs`, and `/.well-known/jwks.json`).
///
/// Returns the JSON Web Key Set containing the server's public signing
/// keys for external token verification, per RFC 7517. Includes one entry
/// per supported algorithm — Ed25519 (`EdDSA`) as the primary signer,
/// plus RSA-2048 (`RS256`) and EC P-256 (`ES256`) for ecosystem
/// compatibility with OIDC clients (e.g. `jose` / `python-jose`).
///
/// Renders the domain [`crate::identity::tokens::JwksDocument`] directly
/// as JSON, bypassing the proto `JsonWebKey` type — that proto only
/// carries the OKP/Ed25519 field set and would drop RSA `n`/`e` and EC
/// `y` coordinates.
async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let doc = state.identity.jwks();
    (StatusCode::OK, Json(doc))
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
    // ROPC (password grant) fields — RFC 6749 §4.3
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// HTTP request body for token revocation (RFC 7009).
///
/// Extends the proto type with optional client credentials for HTTP endpoints.
/// Clients may authenticate via HTTP Basic Auth or via these body fields
/// per RFC 6749 §2.3.1.
#[derive(Debug, Deserialize)]
struct HttpRevocationBody {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// HTTP request body for token introspection (RFC 7662).
///
/// Extends the proto type with optional client credentials for HTTP endpoints.
/// Clients may authenticate via HTTP Basic Auth or via these body fields
/// per RFC 6749 §2.3.1.
#[derive(Debug, Deserialize)]
struct HttpIntrospectionBody {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// Parses HTTP Basic Auth credentials from the `Authorization` header.
///
/// Returns `Some((client_id, client_secret))` on success, `None` if the header
/// is absent or not Basic Auth.
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/// Extracts client credentials from HTTP Basic Auth or body parameters and
/// verifies them against the stored client record.
///
/// Returns the authenticated `ClientId` on success, or a 401 response if
/// client_id is missing, the client does not exist, or the secret is wrong.
/// Confidential clients require a secret; public clients are accepted with
/// client_id alone.
fn verify_endpoint_client(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
) -> Result<ClientId, Response> {
    // Prefer Basic Auth (RFC 6749 §2.3.1); fall back to body parameters.
    let (raw_id, secret) = if let Some((id, sec)) = parse_basic_auth(headers) {
        (id, Some(sec))
    } else if let Some(id) = body_client_id {
        (id.to_string(), body_client_secret.map(str::to_string))
    } else {
        return Err((
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Basic realm=\"hearth\"")],
            Json(serde_json::json!({"error": "client_id required"})),
        )
            .into_response());
    };

    let client_uuid = raw_id.parse::<uuid::Uuid>().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid client credentials"})),
        )
            .into_response()
    })?;
    let client_id = ClientId::new(client_uuid);

    state
        .identity
        .authenticate_client(realm_id, &client_id, secret.as_deref())
        .map(|()| client_id)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid client credentials"})),
            )
                .into_response()
        })
}

/// Returns the CORS `Access-Control-Allow-Origin` value for `origin` if it
/// matches any base origin of a registered client's `redirect_uris`.
///
/// Base origin = scheme + "://" + host (+ optional port). E.g.
/// `https://app.example.com` extracted from `https://app.example.com/callback`.
fn cors_origin_for_client(
    state: &AppState,
    realm_id: &RealmId,
    client_id: &ClientId,
    request_origin: &str,
) -> Option<axum::http::HeaderValue> {
    let client = state.identity.get_client(realm_id, client_id).ok()??;
    let origin_base = extract_origin_base(request_origin)?;
    let allowed = client.redirect_uris().iter().any(|uri| {
        extract_origin_base(uri)
            .map(|base| base == origin_base)
            .unwrap_or(false)
    });
    if allowed {
        axum::http::HeaderValue::from_str(request_origin).ok()
    } else {
        None
    }
}

/// Extracts `scheme://host[:port]` from a URI string.
fn extract_origin_base(uri: &str) -> Option<String> {
    // Fast path: find "://" then take up to the next "/"
    let after_scheme = uri.find("://")?;
    let rest = &uri[after_scheme + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];
    Some(format!("{}://{host}", &uri[..after_scheme]))
}

/// Appends CORS headers to `response` when the request `Origin` is authorised
/// for the given authenticated client.
fn apply_cors_to_response(
    resp: &mut Response,
    state: &AppState,
    realm_id: &RealmId,
    client_id: &ClientId,
    request_headers: &HeaderMap,
) {
    let Some(origin_val) = request_headers.get(axum::http::header::ORIGIN) else {
        return;
    };
    let Ok(origin_str) = origin_val.to_str() else {
        return;
    };
    if let Some(allow_origin) = cors_origin_for_client(state, realm_id, client_id, origin_str) {
        let h = resp.headers_mut();
        h.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            allow_origin,
        );
        h.insert(
            axum::http::HeaderName::from_static("access-control-allow-credentials"),
            axum::http::HeaderValue::from_static("true"),
        );
    }
}

/// Handles `OPTIONS` preflight for token endpoints. Validates that at least
/// one registered client in the realm accepts the requesting origin, then
/// responds `204 No Content` with the required CORS preflight headers.
async fn token_options_preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    realm_id: RealmId,
) -> Response {
    let Some(origin_val) = headers.get(axum::http::header::ORIGIN) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let Ok(origin_str) = origin_val.to_str() else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let Some(origin_base) = extract_origin_base(origin_str) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    // Check whether any registered client accepts this origin.
    let allowed = state
        .identity
        .list_clients(&realm_id, None, 200)
        .ok()
        .map(|page| {
            page.items.iter().any(|c| {
                c.redirect_uris().iter().any(|uri| {
                    extract_origin_base(uri)
                        .map(|base| base == origin_base)
                        .unwrap_or(false)
                })
            })
        })
        .unwrap_or(false);
    if !allowed {
        return StatusCode::NO_CONTENT.into_response();
    }
    let Ok(allow_origin_hv) = axum::http::HeaderValue::from_str(origin_str) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        allow_origin_hv,
    );
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        axum::http::HeaderValue::from_static("POST, OPTIONS"),
    );
    h.insert(
        axum::http::HeaderName::from_static("access-control-allow-headers"),
        axum::http::HeaderValue::from_static("Authorization, Content-Type"),
    );
    h.insert(
        axum::http::HeaderName::from_static("access-control-allow-credentials"),
        axum::http::HeaderValue::from_static("true"),
    );
    h.insert(
        axum::http::HeaderName::from_static("access-control-max-age"),
        axum::http::HeaderValue::from_static("86400"),
    );
    resp
}

/// `OPTIONS /token` — CORS preflight.
async fn token_preflight(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Ok(realm_id) = extract_realm_id(&headers) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    token_options_preflight(State(state), headers, realm_id).await
}

/// `OPTIONS /realms/{realm}/token` — CORS preflight.
async fn realm_token_preflight(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(_) => return StatusCode::NO_CONTENT.into_response(),
    };
    token_options_preflight(State(state), headers, realm_id).await
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
        IdentityError::AuthMethodNotAllowed { .. } => {
            (StatusCode::FORBIDDEN, "authentication method not permitted")
        }
        IdentityError::PasswordExpired => (StatusCode::UNAUTHORIZED, "password expired"),
        IdentityError::PasswordReused => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "password was recently used",
        ),
        IdentityError::AuditFailure { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error: audit record failed",
        ),
        IdentityError::WebhookNotFound => (StatusCode::NOT_FOUND, "webhook not found"),
    };

    let error_code = crate::protocol::error_codes::for_identity_error(err);
    (
        status,
        Json(serde_json::json!({"error": message, "error_code": error_code})),
    )
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

/// RFC 7591 Dynamic Client Registration response.
#[derive(Debug, Serialize)]
struct DcrResponse {
    client_id: String,
    client_secret: String,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    client_secret_expires_at: u64,
    token_endpoint_auth_method: String,
    client_id_issued_at: i64,
}

/// Dynamic Client Registration (RFC 7591) endpoint.
///
/// Accepts `POST /register` with `X-Realm-ID` header. The realm's
/// `dcr_policy` must be `Open` — returns 403 otherwise. The server
/// generates a random client secret and slug; the client does not
/// supply these. Returns an RFC 7591-compatible JSON response.
async fn register_client_dynamic(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::RegisterClientRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Look up the realm to check DCR policy.
    let realm = match state.identity.get_realm(&realm_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "realm not found"})),
            )
                .into_response();
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let dcr_policy = realm.config().dcr_policy.clone().unwrap_or_default();

    if !matches!(dcr_policy, crate::identity::DcrPolicy::Open) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "dynamic client registration is disabled for this realm"})),
        )
            .into_response();
    }

    // Strip any client-supplied secret — the server generates its own.
    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;

    // Generate server-side random secret.
    use base64::Engine as _;
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut secret_bytes = [0u8; 32];
    #[allow(clippy::unwrap_used)]
    // INVARIANT: SystemRandom::fill fails only on catastrophic OS RNG failure.
    rng.fill(&mut secret_bytes).unwrap();
    let generated_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
    request.client_secret = Some(generated_secret.clone());

    // Force ThirdParty trust and consent for DCR-registered clients.
    request.trust_level = crate::identity::ClientTrustLevel::ThirdParty;
    request.require_consent = true;

    // Generate a unique slug: base name + random hex suffix.
    let base_slug = request.client_name.to_lowercase().replace(' ', "-");
    let slug = generate_unique_slug(state.clone(), &realm_id, &base_slug).await;
    request.slug = Some(slug);

    match state.identity.register_client(&realm_id, &request) {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "anonymous".to_string(),
                action: crate::audit::AuditAction::ClientRegistered,
                resource_type: "client".to_string(),
                resource_id: client.client_id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "dynamic_registration"})),
            });

            let response = DcrResponse {
                client_id: client.client_id().as_uuid().to_string(),
                client_secret: generated_secret,
                client_name: client.client_name().to_string(),
                redirect_uris: client.redirect_uris().to_vec(),
                grant_types: client.grant_types().to_vec(),
                client_secret_expires_at: 0,
                token_endpoint_auth_method: "client_secret_basic".to_string(),
                #[allow(clippy::cast_possible_truncation)]
                client_id_issued_at: client.created_at().as_micros() / 1_000_000,
            };

            (
                StatusCode::CREATED,
                Json(serde_json::to_value(response).unwrap_or_default()),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Generates a unique client slug for DCR by appending a random suffix to the
/// base name. Scans existing clients to avoid collisions, retrying up to 5
/// times.
#[allow(dead_code)]
async fn generate_unique_slug(state: Arc<AppState>, realm_id: &RealmId, base: &str) -> String {
    for _ in 0..5 {
        let suffix = uuid::Uuid::new_v4().to_string();
        let candidate = format!("{base}-{}", &suffix[..8]);

        // Check for collision against existing clients.
        match state.identity.list_clients(realm_id, None, 1000) {
            Ok(page) => {
                let collision = page.items.iter().any(|c| c.slug() == candidate);
                if !collision {
                    return candidate;
                }
            }
            Err(_) => {
                // If listing fails, use the candidate anyway — low collision
                // probability makes this acceptable.
                return candidate;
            }
        }
    }

    // After 5 retries, use the last attempt. The 8-hex-char suffix provides
    // ~2^32 collision space — retries are a belt-and-suspenders guard.
    let suffix = uuid::Uuid::new_v4().to_string();
    format!("{base}-{}", &suffix[..8])
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
async fn token_exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpTokenRequest>,
) -> Response {
    // Parse client_id and realm_id before dispatch so CORS can be applied to
    // every response path, including grant-type-specific error branches.
    let maybe_client_id = body.client_id.parse::<uuid::Uuid>().ok().map(ClientId::new);
    let maybe_realm_id = extract_realm_id(&headers).ok();

    let mut resp = token_exchange_impl(Arc::clone(&state), headers.clone(), body).await;

    if let (Some(ref realm_id), Some(ref client_id)) = (&maybe_realm_id, &maybe_client_id) {
        apply_cors_to_response(&mut resp, &state, realm_id, client_id, &headers);
    }
    resp
}

/// Inner implementation of [`token_exchange`].
///
/// Separated from the outer handler so that CORS application can wrap all
/// exit paths without touching every early-return site.
#[allow(clippy::too_many_lines)]
async fn token_exchange_impl(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: HttpTokenRequest,
) -> Response {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Rate limit per client_id before any grant-type dispatch.
    if let Ok(client_uuid) = body.client_id.parse::<uuid::Uuid>() {
        let client_id = ClientId::new(client_uuid);
        if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
            return resp;
        }
    }

    let grant_type = body.grant_type.as_deref().unwrap_or("authorization_code");

    // Per-IP rate limiting for the ROPC password grant.
    // In production traffic goes through a reverse proxy so the real IP
    // arrives via X-Forwarded-For; FALLBACK_PEER is used when ConnectInfo is
    // unavailable (e.g. tower::ServiceExt::oneshot in tests).
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    if grant_type == "password"
        && state
            .identity
            .check_ip_login_rate_limit(&realm_id, &client_ip)
            .is_err()
    {
        let retry_after = state
            .identity
            .ip_login_retry_after_secs(&realm_id, &client_ip);
        return make_ip_rate_limit_response(retry_after as u32);
    }

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
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[
                            realm_id.as_uuid().to_string().as_str(),
                            "authorization_code",
                        ])
                        .inc();
                    crate::metrics::metrics().active_sessions.inc();
                    (
                        StatusCode::OK,
                        Json(proto_to_rest_json(&pb::OidcTokenResponse::from(&response))),
                    )
                        .into_response()
                }
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
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[
                            realm_id.as_uuid().to_string().as_str(),
                            "refresh_token",
                        ])
                        .inc();
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

            let realm_str = realm_id.as_uuid().to_string();
            match state.identity.client_credentials_token(&realm_id, &request) {
                Ok(response) => {
                    crate::metrics::metrics()
                        .auth_attempts_total
                        .with_label_values(&[realm_str.as_str(), "success"])
                        .inc();
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[realm_str.as_str(), "client_credentials"])
                        .inc();
                    (
                        StatusCode::OK,
                        Json(proto_to_rest_json(&pb::ClientCredentialsResponse::from(
                            &response,
                        ))),
                    )
                        .into_response()
                }
                Err(e) => {
                    crate::metrics::metrics()
                        .auth_attempts_total
                        .with_label_values(&[realm_str.as_str(), "failure"])
                        .inc();
                    identity_error_to_response(&e).into_response()
                }
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

            let oauth_client_id = match body.client_id.parse::<uuid::Uuid>() {
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
                .poll_device_token(&realm_id, &device_code, &oauth_client_id)
            {
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[
                            realm_id.as_uuid().to_string().as_str(),
                            "urn:ietf:params:oauth:grant-type:device_code",
                        ])
                        .inc();
                    crate::metrics::metrics().active_sessions.inc();
                    (
                        StatusCode::OK,
                        Json(proto_to_rest_json(&pb::OidcTokenResponse::from(&response))),
                    )
                        .into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "password" => {
            let (Some(email), Some(password)) = (body.username, body.password) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "username and password required for password grant"})),
                )
                    .into_response();
            };
            let request = PasswordGrantRequest {
                email,
                password,
                scope: body.scope,
            };
            let realm_str = realm_id.as_uuid().to_string();
            match state.identity.password_grant_token(&realm_id, &request) {
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[realm_str.as_str(), "password"])
                        .inc();
                    crate::metrics::metrics().active_sessions.inc();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": response.access_token(),
                            "refresh_token": response.refresh_token(),
                            "token_type": response.token_type,
                            "expires_in": response.expires_in,
                        })),
                    )
                        .into_response()
                }
                Err(
                    ref e @ (crate::identity::IdentityError::InvalidCredential { .. }
                    | crate::identity::IdentityError::RateLimited),
                ) => {
                    // Record the failed attempt against the IP for credential failures.
                    state
                        .identity
                        .record_ip_login_attempt(&realm_id, &client_ip);
                    identity_error_to_response(e).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "unsupported_grant_type",
                "error_code": crate::protocol::error_codes::UNSUPPORTED_GRANT_TYPE,
            })),
        )
            .into_response(),
    }
}

// === Token Revocation (RFC 7009) ===

/// POST /revoke — revokes an OAuth 2.0 token.
///
/// Per RFC 7009, returns 200 OK regardless of whether the token was
/// actually revoked (to prevent information leakage). Requires client
/// authentication via HTTP Basic Auth or body `client_id`/`client_secret`.
async fn token_revocation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpRevocationBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let client_id = match verify_endpoint_client(
        &state,
        &realm_id,
        &headers,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
        return resp;
    }

    let request = crate::identity::TokenRevocationRequest {
        token: body.token,
        token_type_hint: body.token_type_hint,
    };

    let mut resp = match state.identity.revoke_token(&realm_id, &request) {
        Ok(()) => {
            // A successful revoke ends a session; keep the gauge consistent.
            crate::metrics::metrics().active_sessions.dec();
            StatusCode::OK.into_response()
        }
        Err(crate::identity::IdentityError::InvalidToken) => {
            // RFC 7009: always return 200 OK
            StatusCode::OK.into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    };
    apply_cors_to_response(&mut resp, &state, &realm_id, &client_id, &headers);
    resp
}

// === Token Introspection (RFC 7662) ===

/// POST /introspect — introspects an OAuth 2.0 token.
///
/// Returns metadata about the token including its active status. Requires
/// client authentication via HTTP Basic Auth or body `client_id`/`client_secret`.
async fn token_introspection(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpIntrospectionBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let client_id = match verify_endpoint_client(
        &state,
        &realm_id,
        &headers,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
        return resp;
    }

    let request = crate::identity::TokenIntrospectionRequest {
        token: body.token,
        token_type_hint: body.token_type_hint,
    };

    let mut resp = match state.identity.introspect_token(&realm_id, &request) {
        // Use the domain type directly: the domain IntrospectionResponse has
        // #[derive(Serialize)] and always emits `active: false` for inactive
        // tokens. The proto-generated serde omits proto3 default values (false)
        // which would violate RFC 7662 §2.2 by leaving `active` absent.
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    };
    apply_cors_to_response(&mut resp, &state, &realm_id, &client_id, &headers);
    resp
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
    if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
        return resp;
    }

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
        RbacError::RoleArchived => (StatusCode::CONFLICT, "role_archived"),
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

/// Pagination query parameters (also carries optional search query and field filters).
#[derive(Debug, Deserialize)]
struct PaginationParams {
    cursor: Option<String>,
    limit: Option<usize>,
    search: Option<String>,
    /// Exact email filter (case-insensitive, applied after normalisation).
    email: Option<String>,
    /// Substring filter on `display_name` (case-insensitive).
    username: Option<String>,
    /// Status filter: accepts `"active"`, `"disabled"`, or `"pending_verification"`.
    status: Option<String>,
}

impl PaginationParams {
    /// Returns the limit clamped to [1, 100] with a default of 20.
    fn effective_limit(&self) -> usize {
        self.limit.unwrap_or(20).clamp(1, 100)
    }
}

/// Admin: list users (paginated), search when `?search=<q>` is present, or
/// field-filter when `?email=`, `?username=`, or `?status=` are present.
async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    if let Some(q) = &params.search {
        // Short queries return empty results immediately (no index hit).
        if q.len() < 2 {
            return (
                StatusCode::OK,
                Json(serde_json::json!({"items": [], "next_cursor": null})),
            )
                .into_response();
        }
        return match state
            .identity
            .search_users(&auth.realm_id, q, params.effective_limit())
        {
            Ok(users) => {
                let items: Vec<serde_json::Value> = users
                    .iter()
                    .map(|u| proto_to_rest_json(&pb::User::from(u)))
                    .collect();
                (
                    StatusCode::OK,
                    Json(serde_json::json!({"items": items, "next_cursor": null})),
                )
                    .into_response()
            }
            Err(e) => identity_error_to_response(&e).into_response(),
        };
    }

    let has_field_filters =
        params.email.is_some() || params.username.is_some() || params.status.is_some();

    if has_field_filters {
        // Parse the status filter value if provided.
        let status_filter = if let Some(s) = &params.status {
            let parsed = match s.as_str() {
                "active" => Some(crate::identity::UserStatus::Active),
                "disabled" => Some(crate::identity::UserStatus::Disabled),
                "pending_verification" => Some(crate::identity::UserStatus::PendingVerification),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid status filter; expected active, disabled, or pending_verification"})),
                    )
                        .into_response();
                }
            };
            parsed
        } else {
            None
        };

        // Full scan up to a bounded cap, then apply predicates. Filtered results
        // don't support cursor pagination — next_cursor is always null.
        const FILTER_SCAN_CAP: usize = 10_000;
        let all_users = match state
            .identity
            .list_users(&auth.realm_id, None, FILTER_SCAN_CAP)
        {
            Ok(page) => page.items,
            Err(e) => return identity_error_to_response(&e).into_response(),
        };

        let email_norm = params.email.as_deref().map(|e| e.to_lowercase());
        let username_lower = params.username.as_deref().map(|u| u.to_lowercase());

        let items: Vec<serde_json::Value> = all_users
            .iter()
            .filter(|u| {
                if let Some(ref ef) = email_norm {
                    if u.email() != ef.as_str() {
                        return false;
                    }
                }
                if let Some(ref uf) = username_lower {
                    if !u.display_name().to_lowercase().contains(uf.as_str()) {
                        return false;
                    }
                }
                if let Some(sf) = status_filter {
                    if u.status() != sf {
                        return false;
                    }
                }
                true
            })
            .take(params.effective_limit())
            .map(|u| proto_to_rest_json(&pb::User::from(u)))
            .collect();

        return (
            StatusCode::OK,
            Json(serde_json::json!({"items": items, "next_cursor": null})),
        )
            .into_response();
    }

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

/// Import request body — one entry per user to import.
#[derive(Debug, Deserialize)]
struct ImportUsersBody {
    users: Vec<ImportUserEntry>,
}

/// Single user entry in a bulk import request.
#[derive(Debug, Deserialize)]
struct ImportUserEntry {
    email: String,
    display_name: String,
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
    /// Accepts `"active"`, `"disabled"`, `"suspended"`, or `"pending_verification"`.
    status: Option<String>,
    #[serde(default)]
    attributes: std::collections::BTreeMap<String, String>,
}

/// Admin: bulk import users (`POST /admin/users/import`).
async fn admin_import_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ImportUsersBody>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    if body.users.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "users array must not be empty"})),
        )
            .into_response();
    }

    const MAX_BULK_IMPORT: usize = 10_000;
    if body.users.len() > MAX_BULK_IMPORT {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("batch size {n} exceeds maximum of {MAX_BULK_IMPORT}", n = body.users.len())})),
        )
            .into_response();
    }

    let mut imported = 0u32;
    let mut failed = 0u32;
    let mut results = Vec::with_capacity(body.users.len());

    for entry in &body.users {
        let status = match entry.status.as_deref().unwrap_or("active") {
            "active" => crate::identity::UserStatus::Active,
            "disabled" => crate::identity::UserStatus::Disabled,
            "pending_verification" => crate::identity::UserStatus::PendingVerification,
            other => {
                failed += 1;
                results.push(serde_json::json!({
                    "email": entry.email,
                    "error": format!("unknown status: {other}")
                }));
                continue;
            }
        };

        let req = crate::identity::ImportUserRequest {
            id: None,
            email: entry.email.clone(),
            display_name: entry.display_name.clone(),
            first_name: entry.first_name.clone(),
            last_name: entry.last_name.clone(),
            status,
            credential: None,
            attributes: entry.attributes.clone(),
        };

        match state.identity.import_user(&auth.realm_id, &req) {
            Ok(u) => {
                imported += 1;
                results.push(serde_json::json!({
                    "email": entry.email,
                    "id": u.id().as_uuid().to_string(),
                    "error": null
                }));
            }
            Err(e) => {
                failed += 1;
                results.push(serde_json::json!({
                    "email": entry.email,
                    "error": e.to_string()
                }));
            }
        }
    }

    let total = imported + failed;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "imported": imported,
            "failed": failed,
            "total": total,
            "results": results
        })),
    )
        .into_response()
}

/// Export format query parameter.
#[derive(Debug, Deserialize)]
struct ExportParams {
    format: Option<String>,
}

/// Admin: bulk export users (`GET /admin/users/export`).
///
/// Default format is JSON (`{"count": N, "users": [...]}`).
/// Pass `?format=ndjson` for newline-delimited JSON (one object per line).
async fn admin_export_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    // Collect all users by draining pages.
    let mut all_users: Vec<crate::identity::User> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = match state
            .identity
            .list_users(&auth.realm_id, cursor.as_deref(), 100)
        {
            Ok(p) => p,
            Err(e) => return identity_error_to_response(&e).into_response(),
        };
        all_users.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    let user_to_json = |u: &crate::identity::User| -> serde_json::Value {
        let mut v = proto_to_rest_json(&pb::User::from(u));
        if !u.attributes().is_empty() {
            v["attributes"] = serde_json::json!(u.attributes());
        }
        v
    };

    let ndjson = params.format.as_deref() == Some("ndjson");
    if ndjson {
        let mut body = String::new();
        for u in &all_users {
            body.push_str(&serde_json::to_string(&user_to_json(u)).unwrap_or_default());
            body.push('\n');
        }
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
            body,
        )
            .into_response();
    }

    let users: Vec<serde_json::Value> = all_users.iter().map(user_to_json).collect();
    let count = users.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({"count": count, "users": users})),
    )
        .into_response()
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

/// Admin: rotate the Ed25519 signing key for a realm.
///
/// Generates a new key, promotes it to the active key, and keeps the old key
/// in the JWKS response for the configured grace period (default 24 h) so
/// tokens signed with the old key remain valid during that window.
async fn admin_rotate_realm_signing_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let _ = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let grace_period_secs = state.signing_key_rotation_grace_period_secs;

    match state
        .identity
        .rotate_realm_signing_key(&realm_id, grace_period_secs)
    {
        Ok(()) => {
            let _ = state.audit.append(&crate::audit::CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::RealmUpdated,
                resource_type: "realm".to_string(),
                resource_id: realm_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({"action": "rotate_signing_key", "grace_period_secs": grace_period_secs})),
            });
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": "signing key rotated",
                    "grace_period_secs": grace_period_secs
                })),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Realm branding & email-template admin API
// ---------------------------------------------------------------------------

/// Request body for `PATCH /realms/{id}/branding`.
#[derive(Debug, Deserialize)]
struct PatchRealmBrandingRequest {
    #[serde(default)]
    logo_url: Option<String>,
    #[serde(default)]
    primary_color: Option<String>,
    /// Email-level branding (accent_color, support_email, custom_footer_text).
    #[serde(default)]
    email_branding: Option<EmailBranding>,
}

/// Response body for `GET /realms/{id}/branding`.
#[derive(Debug, Serialize)]
struct RealmBrandingResponse {
    logo_url: Option<String>,
    primary_color: Option<String>,
    email_branding: Option<EmailBranding>,
}

/// Parses a realm UUID from a path segment, returning 400 on bad input.
fn parse_realm_id(id: &str) -> Result<RealmId, Response> {
    id.parse::<uuid::Uuid>().map(RealmId::new).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid realm ID"})),
        )
            .into_response()
    })
}

/// Resolves a live realm by ID, returning 404 when absent.
fn require_realm(state: &AppState, realm_id: &RealmId) -> Result<crate::identity::Realm, Response> {
    match state.identity.get_realm(realm_id) {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "realm not found"})),
        )
            .into_response()),
        Err(e) => Err(identity_error_to_response(&e).into_response()),
    }
}

/// `GET /realms/{id}/branding` — return current per-realm branding settings.
async fn admin_get_realm_branding(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = extract_admin_auth(&headers, &state) {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let cfg = realm.config();
    (
        StatusCode::OK,
        Json(RealmBrandingResponse {
            logo_url: cfg.logo_url.clone(),
            primary_color: cfg.primary_color.clone(),
            email_branding: cfg.email_branding.clone(),
        }),
    )
        .into_response()
}

/// `PATCH /realms/{id}/branding` — update per-realm branding settings.
///
/// Only fields present in the request body are updated; omitted fields are
/// left unchanged. Use `null` to clear a previously-set value.
async fn admin_patch_realm_branding(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PatchRealmBrandingRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Validate hex color format if provided.
    if let Some(color) = body.primary_color.as_deref() {
        if !color.starts_with('#') || (color.len() != 4 && color.len() != 7) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "invalid_color",
                    "message": "primary_color must be a CSS hex color (#RGB or #RRGGBB)"
                })),
            )
                .into_response();
        }
    }

    let mut new_config = realm.config().clone();
    // Merge: explicit `Some` overwrites; `None` in request body clears.
    // The PATCH semantics here treat the request as a partial update where
    // serde's `#[serde(default)]` delivers `None` for absent fields — so
    // we only overwrite when the caller explicitly sent the field.
    // Use JSON `null` to explicitly clear a field.
    if body.logo_url.is_some() {
        new_config.logo_url = body.logo_url;
    }
    if body.primary_color.is_some() {
        new_config.primary_color = body.primary_color;
    }
    if body.email_branding.is_some() {
        new_config.email_branding = body.email_branding;
    }

    match state.identity.update_realm(
        &realm_id,
        &UpdateRealmRequest {
            config: Some(new_config),
            ..UpdateRealmRequest::default()
        },
    ) {
        Ok(updated) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::RealmUpdated,
                resource_type: "realm".to_string(),
                resource_id: realm_id.as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api", "op": "patch_branding"})),
            });
            let cfg = updated.config();
            (
                StatusCode::OK,
                Json(RealmBrandingResponse {
                    logo_url: cfg.logo_url.clone(),
                    primary_color: cfg.primary_color.clone(),
                    email_branding: cfg.email_branding.clone(),
                }),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /realms/{id}/email-templates` — list all stored template overrides.
async fn admin_list_realm_email_templates(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = extract_admin_auth(&headers, &state) {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    (StatusCode::OK, Json(realm.config().email_templates.clone())).into_response()
}

/// `GET /realms/{id}/email-templates/{kind}` — get a single stored template.
async fn admin_get_realm_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, kind)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = extract_admin_auth(&headers, &state) {
        return e.into_response();
    }
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    match realm.config().email_templates.get(&kind) {
        Some(tmpl) => (StatusCode::OK, Json(tmpl.clone())).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "template not found"})),
        )
            .into_response(),
    }
}

/// `PUT /realms/{id}/email-templates/{kind}` — upsert a stored template.
///
/// Validates that all `{{placeholder}}` tokens in the body are in the
/// allowlist for the given template kind before persisting.
async fn admin_put_realm_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, kind)): Path<(String, String)>,
    Json(body): Json<LocalizedEmailTemplate>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Validate template kind and placeholders in all body fields.
    let fields_to_validate: Vec<(&str, &str)> = {
        let mut v = Vec::new();
        if let Some(ref s) = body.default.subject {
            v.push(("default.subject", s.as_str()));
        }
        if let Some(ref s) = body.default.html_body {
            v.push(("default.html_body", s.as_str()));
        }
        if let Some(ref s) = body.default.text_body {
            v.push(("default.text_body", s.as_str()));
        }
        for (locale, lb) in &body.locales {
            if let Some(ref s) = lb.subject {
                v.push((locale.as_str(), s.as_str()));
            }
            if let Some(ref s) = lb.html_body {
                v.push((locale.as_str(), s.as_str()));
            }
            if let Some(ref s) = lb.text_body {
                v.push((locale.as_str(), s.as_str()));
            }
        }
        v
    };

    for (_field, text) in &fields_to_validate {
        if let Err(e) = validate_email_template(&kind, text) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "invalid_template",
                    "message": format!("{e}")
                })),
            )
                .into_response();
        }
    }

    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let mut new_config = realm.config().clone();
    new_config.email_templates.insert(kind.clone(), body);

    match state.identity.update_realm(
        &realm_id,
        &UpdateRealmRequest {
            config: Some(new_config),
            ..UpdateRealmRequest::default()
        },
    ) {
        Ok(updated) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::RealmUpdated,
                resource_type: "realm".to_string(),
                resource_id: realm_id.as_uuid().to_string(),
                metadata: Some(
                    serde_json::json!({"via": "admin_api", "op": "put_email_template", "kind": kind}),
                ),
            });
            match updated.config().email_templates.get(&kind) {
                Some(tmpl) => (StatusCode::OK, Json(tmpl.clone())).into_response(),
                None => StatusCode::NO_CONTENT.into_response(),
            }
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /realms/{id}/email-templates/{kind}` — remove a stored template override.
async fn admin_delete_realm_email_template(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, kind)): Path<(String, String)>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = match parse_realm_id(&id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let realm = match require_realm(&state, &realm_id) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if !realm.config().email_templates.contains_key(&kind) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "template not found"})),
        )
            .into_response();
    }
    let mut new_config = realm.config().clone();
    new_config.email_templates.remove(&kind);

    match state.identity.update_realm(
        &realm_id,
        &UpdateRealmRequest {
            config: Some(new_config),
            ..UpdateRealmRequest::default()
        },
    ) {
        Ok(_) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::RealmUpdated,
                resource_type: "realm".to_string(),
                resource_id: realm_id.as_uuid().to_string(),
                metadata: Some(
                    serde_json::json!({"via": "admin_api", "op": "delete_email_template", "kind": kind}),
                ),
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

/// JSON body for `PUT /admin/applications/{id}`.
///
/// Extends the proto `UpdateClientRequest` with logout URI fields that are
/// not (yet) in the proto schema.
#[derive(Debug, Deserialize, Default)]
struct AdminUpdateClientBody {
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    /// Back-channel logout URI. `null` clears it; omit to leave unchanged.
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    backchannel_logout_uri: Option<Option<String>>,
    /// Front-channel logout URI. `null` clears it; omit to leave unchanged.
    #[serde(default, deserialize_with = "deserialize_nullable_string")]
    frontchannel_logout_uri: Option<Option<String>>,
    /// Replaces the allowed post-logout redirect URI list.
    post_logout_redirect_uris: Option<Vec<String>>,
}

/// Deserializes an optional nullable string field.
///
/// - Field absent → `None` (leave unchanged)
/// - `null` → `Some(None)` (clear the field)
/// - `"uri"` → `Some(Some("uri"))` (set to value)
fn deserialize_nullable_string<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    // Option<Option<String>> naturally handles null vs absent vs string.
    Option::<Option<String>>::deserialize(d)
}

/// Admin: update client by ID.
async fn admin_update_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AdminUpdateClientBody>,
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

    let request = crate::identity::UpdateClientRequest {
        client_name: body.client_name,
        redirect_uris: if body.redirect_uris.is_empty() {
            None
        } else {
            Some(body.redirect_uris)
        },
        grant_types: if body.grant_types.is_empty() {
            None
        } else {
            Some(body.grant_types)
        },
        backchannel_logout_uri: body.backchannel_logout_uri,
        frontchannel_logout_uri: body.frontchannel_logout_uri,
        post_logout_redirect_uris: body.post_logout_redirect_uris,
        ..Default::default()
    };

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

/// `GET /admin/users/{id}/effective-permissions` — resolves the effective
/// roles, groups, and permissions for a given user in the admin's realm.
///
/// Accepts optional `org_id` and `scope` query parameters. Returns the
/// same response shape as `GET /v1/me/permissions` but scoped to an
/// arbitrary user (admin-only).
async fn admin_get_user_effective_permissions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(user_id_str): axum::extract::Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
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

    // Precheck: the target user must exist in the admin's realm.
    match state.identity.get_user(&auth.realm_id, &user_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            )
                .into_response();
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    }

    let org_id = match params.get("org_id") {
        Some(s) => {
            let stripped = s.strip_prefix("org_").unwrap_or(s);
            match uuid::Uuid::parse_str(stripped) {
                Ok(u) => Some(crate::core::OrganizationId::new(u)),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid org_id"})),
                    )
                        .into_response();
                }
            }
        }
        None => None,
    };
    let scope = params.get("scope").cloned();

    let resolved = match state.rbac.resolve_permissions(
        &user_id,
        &auth.realm_id,
        org_id.as_ref(),
        scope.as_deref(),
    ) {
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

    // Seed RBAC defaults on the new realm. Hard error: a dev bootstrap
    // with a broken seed produces a realm where the admin user cannot be
    // granted realm.admin, making the bootstrap useless.
    if let Err(e) = state.rbac.seed_realm(&realm_id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("RBAC seed failed: {e}")})),
        )
            .into_response();
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

    let realm_id_str = realm_id.as_uuid().to_string();
    let access_token_str = tokens.access_token().to_string();
    let quickstart = format!(
        r#"# 1. Register an OAuth application
curl -fsS -X POST http://127.0.0.1:8420/clients \
  -H "Authorization: Bearer {access_token_str}" \
  -H "X-Realm-ID: {realm_id_str}" \
  -H "Content-Type: application/json" \
  -d '{{"client_name":"my-app","redirect_uris":["https://myapp.example.com/callback"]}}'

# 2. Full PKCE flow — see docs/guides/getting-started.md"#
    );

    (
        StatusCode::OK,
        Json(pb::BootstrapResponse {
            realm_id: realm_id_str,
            user_id: user_id.as_uuid().to_string(),
            access_token: access_token_str,
            refresh_token: tokens.refresh_token().to_string(),
            quickstart,
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
            status: None,
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

// ============================================================================
// WebAuthn / Passkey REST API
// ============================================================================

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

fn b64_decode(s: &str) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid base64url: {e}")})),
        )
    })
}

fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

#[derive(Debug, Deserialize)]
struct WbrBeginReq {
    rp_id: Option<String>,
    discoverable: Option<bool>,
}

#[derive(Debug, Serialize)]
struct WbrBeginRes {
    challenge: String,
    rp_id: String,
    rp_name: String,
    user_id: String,
    user_name: String,
    user_display_name: String,
    attestation: String,
    timeout: u64,
}

#[derive(Debug, Deserialize)]
struct WbrCompleteReq {
    client_data_json: String,
    attestation_object: String,
    origin: String,
    discoverable: Option<bool>,
}

#[derive(Debug, Serialize)]
struct WbrCompleteRes {
    credential_id: String,
    algorithm: i64,
    discoverable: bool,
}

#[derive(Debug, Deserialize)]
struct WbaBeginReq {
    rp_id: Option<String>,
    user_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct WbaBeginRes {
    challenge: String,
    rp_id: String,
    allow_credentials: Vec<WbaAllowCred>,
    user_verification: String,
    timeout: u64,
}

#[derive(Debug, Serialize)]
struct WbaAllowCred {
    id: String,
    #[serde(rename = "type")]
    ty: String,
}

#[derive(Debug, Deserialize)]
struct WbaCompleteReq {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option<String>,
    origin: String,
}

#[derive(Debug, Serialize)]
struct WbaCompleteRes {
    credential_id: String,
    user_id: String,
    sign_count: u32,
}

#[derive(Debug, Serialize)]
struct WbCredsRes {
    credentials: Vec<WbCredEntry>,
}

#[derive(Debug, Serialize)]
struct WbCredEntry {
    credential_id: String,
    algorithm: i64,
    discoverable: bool,
}

async fn webauthn_register_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WbrBeginReq>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let options = crate::identity::webauthn::RegistrationOptions {
        rp_id: body.rp_id.unwrap_or_default(),
        discoverable: body.discoverable.unwrap_or(true),
    };
    match state
        .identity
        .start_webauthn_registration(&realm_id, &user_id, &options)
    {
        Ok(challenge) => (
            StatusCode::OK,
            Json(WbrBeginRes {
                challenge: b64_encode(&challenge),
                rp_id: options.rp_id,
                rp_name: "Hearth".to_string(),
                user_id: user_id.to_string(),
                user_name: user_id.to_string(),
                user_display_name: user_id.to_string(),
                attestation: "none".to_string(),
                timeout: 60,
            }),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_register_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WbrCompleteReq>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let client_data_json = match b64_decode(&body.client_data_json) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let attestation_object = match b64_decode(&body.attestation_object) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state.identity.complete_webauthn_registration(
        &realm_id,
        &user_id,
        &client_data_json,
        &attestation_object,
        &body.origin,
        body.discoverable.unwrap_or(false),
    ) {
        Ok(info) => (
            StatusCode::OK,
            Json(WbrCompleteRes {
                credential_id: b64_encode(info.credential_id()),
                algorithm: info.algorithm(),
                discoverable: info.discoverable(),
            }),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_auth_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WbaBeginReq>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id: Option<UserId> = match body.user_id.as_deref().map(uuid::Uuid::parse_str) {
        Some(Ok(u)) => Some(UserId::new(u)),
        Some(Err(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user_id"})),
            )
                .into_response()
        }
        None => None,
    };
    let options = crate::identity::webauthn::AuthenticationOptions {
        rp_id: body.rp_id.unwrap_or_default(),
    };
    match state
        .identity
        .start_webauthn_authentication(&realm_id, user_id.as_ref(), &options)
    {
        Ok(challenge) => {
            let allow_credentials = match user_id.as_ref() {
                Some(uid) => match state.identity.list_webauthn_credentials(&realm_id, uid) {
                    Ok(creds) => creds
                        .into_iter()
                        .map(|c| WbaAllowCred {
                            id: b64_encode(c.credential_id()),
                            ty: "public-key".to_string(),
                        })
                        .collect(),
                    Err(_) => Vec::new(),
                },
                None => Vec::new(),
            };
            (
                StatusCode::OK,
                Json(WbaBeginRes {
                    challenge: b64_encode(&challenge),
                    rp_id: options.rp_id,
                    allow_credentials,
                    user_verification: "preferred".to_string(),
                    timeout: 60,
                }),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_auth_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WbaCompleteReq>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let credential_id = match b64_decode(&body.credential_id) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let client_data_json = match b64_decode(&body.client_data_json) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let authenticator_data = match b64_decode(&body.authenticator_data) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let signature = match b64_decode(&body.signature) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let uh_vec = match body
        .user_handle
        .as_deref()
        .map(|s| b64_decode(s))
        .transpose()
    {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let params = crate::identity::webauthn::CompleteAuthenticationParams {
        credential_id: &credential_id,
        client_data_json: &client_data_json,
        authenticator_data: &authenticator_data,
        signature: &signature,
        user_handle: uh_vec.as_deref(),
        origin: &body.origin,
    };
    match state
        .identity
        .complete_webauthn_authentication(&realm_id, &params)
    {
        Ok(result) => (
            StatusCode::OK,
            Json(WbaCompleteRes {
                credential_id: b64_encode(result.credential_id()),
                user_id: result.user_id().to_string(),
                sign_count: result.sign_count(),
            }),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    match state
        .identity
        .list_webauthn_credentials(&realm_id, &user_id)
    {
        Ok(creds) => (
            StatusCode::OK,
            Json(WbCredsRes {
                credentials: creds
                    .into_iter()
                    .map(|c| WbCredEntry {
                        credential_id: b64_encode(c.credential_id()),
                        algorithm: c.algorithm(),
                        discoverable: c.discoverable(),
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_delete_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(credential_id_b64): Path<String>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let credential_id = match b64_decode(&credential_id_b64) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state
        .identity
        .revoke_webauthn_credential(&realm_id, &user_id, &credential_id)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// ===== Per-realm OIDC routes ============================================================
//
// Each handler resolves the realm by URL-path name and forwards to the same
// underlying engine methods as the global routes. Token `iss` claims are
// automatically scoped to `{base_issuer}/realms/{name}`.

fn resolve_realm_by_name(
    state: &AppState,
    name: &str,
) -> Result<RealmId, axum::response::Response> {
    match state.identity.get_realm_by_name(name) {
        Ok(Some(realm)) => Ok(realm.id().clone()),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "realm_not_found"})),
        )
            .into_response()),
        Err(e) => {
            tracing::warn!(error = %e, realm_name = %name, "realm lookup failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal_error"})),
            )
                .into_response())
        }
    }
}

/// POST /v1/{realm}/auth/magic-link
///
/// Requests a magic-link login email. Always returns 202 regardless of whether
/// the email is registered (enumeration resistance). Returns 429 when the
/// caller's IP has exceeded the per-IP rate limit.
#[derive(Deserialize)]
struct MagicLinkRequestBody {
    email: String,
}

async fn magic_link_request(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MagicLinkRequestBody>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };

    // Per-IP rate limit. Real IP arrives via X-Forwarded-For in production;
    // FALLBACK_PEER is used when ConnectInfo is unavailable (tests).
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    if state
        .identity
        .check_ip_login_rate_limit(&realm_id, &client_ip)
        .is_err()
    {
        let retry_after = state
            .identity
            .ip_login_retry_after_secs(&realm_id, &client_ip);
        return make_ip_rate_limit_response(retry_after as u32);
    }

    // Request magic link; ignore per-email RateLimited to prevent enumeration.
    let _ = state.identity.request_magic_link(&realm_id, &body.email);

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "message": "If an account exists, a magic link has been sent"
        })),
    )
        .into_response()
}

async fn realm_oidc_discovery(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    match state.identity.realm_oidc_discovery(&realm_id) {
        Ok(doc) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::OidcDiscoveryDocument::from(&doc))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_jwks(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    match state.identity.realm_jwks(&realm_id) {
        Ok(doc) => (StatusCode::OK, Json(doc)).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_authorize(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<pb::AuthorizationRequest>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let request = match proto_authorize_to_domain(body) {
        Ok(r) => r,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
                .into_response()
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

#[allow(clippy::too_many_lines)]
async fn realm_token_exchange(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<HttpTokenRequest>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    // Rate limit per client_id before any grant-type dispatch.
    if let Ok(client_uuid) = body.client_id.parse::<uuid::Uuid>() {
        let client_id = ClientId::new(client_uuid);
        if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
            return resp;
        }
    }
    let grant_type = body.grant_type.as_deref().unwrap_or("authorization_code");

    // Per-IP rate limiting for the ROPC password grant.
    // Real IP arrives via X-Forwarded-For in production; FALLBACK_PEER used in tests.
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    if grant_type == "password"
        && state
            .identity
            .check_ip_login_rate_limit(&realm_id, &client_ip)
            .is_err()
    {
        let retry_after = state
            .identity
            .ip_login_retry_after_secs(&realm_id, &client_ip);
        return make_ip_rate_limit_response(retry_after as u32);
    }
    match grant_type {
        "authorization_code" => {
            let (Some(code), Some(redirect_uri)) = (body.code, body.redirect_uri) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "code and redirect_uri required"})),
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
                        .into_response()
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
                    Json(serde_json::json!({"error": "refresh_token required"})),
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
                        .into_response()
                }
            };
            match state.identity.client_credentials_token(&realm_id, &request) {
                Ok(response) => {
                    let resp = pb::OidcTokenResponse {
                        access_token: response.access_token().to_string(),
                        id_token: String::new(),
                        token_type: "Bearer".to_string(),
                        expires_in: response.expires_in(),
                        refresh_token: String::new(),
                    };
                    (StatusCode::OK, Json(proto_to_rest_json(&resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let Some(device_code) = body.device_code else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "device_code required"})),
                )
                    .into_response();
            };
            let oauth_client_id = match body.client_id.parse::<uuid::Uuid>() {
                Ok(u) => ClientId::new(u),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid client_id UUID"})),
                    )
                        .into_response()
                }
            };
            match state
                .identity
                .poll_device_token(&realm_id, &device_code, &oauth_client_id)
            {
                Ok(response) => (
                    StatusCode::OK,
                    Json(proto_to_rest_json(&pb::OidcTokenResponse::from(&response))),
                )
                    .into_response(),
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "password" => {
            let (Some(email), Some(password)) = (body.username, body.password) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "username and password required for password grant"})),
                )
                    .into_response();
            };
            let request = PasswordGrantRequest {
                email,
                password,
                scope: body.scope,
            };
            match state.identity.password_grant_token(&realm_id, &request) {
                Ok(response) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "access_token": response.access_token(),
                        "refresh_token": response.refresh_token(),
                        "token_type": response.token_type,
                        "expires_in": response.expires_in,
                    })),
                )
                    .into_response(),
                Err(
                    ref e @ (crate::identity::IdentityError::InvalidCredential { .. }
                    | crate::identity::IdentityError::RateLimited),
                ) => {
                    state
                        .identity
                        .record_ip_login_attempt(&realm_id, &client_ip);
                    identity_error_to_response(e).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        other => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("unsupported grant_type: {other}")})),
        )
            .into_response(),
    }
}

async fn realm_token_revocation(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "token required"})),
            )
                .into_response()
        }
    };
    let request = crate::identity::TokenRevocationRequest {
        token,
        token_type_hint: None,
    };
    match state.identity.revoke_token(&realm_id, &request) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_token_introspection(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "token required"})),
            )
                .into_response()
        }
    };
    let request = crate::identity::TokenIntrospectionRequest {
        token,
        token_type_hint: None,
    };
    match state.identity.introspect_token(&realm_id, &request) {
        Ok(info) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::IntrospectionResponse::from(&info))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_userinfo(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
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
    match state.identity.userinfo(&realm_id, token) {
        Ok(info) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::UserInfoResponse::from(&info))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_device_authorization(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let client_id_str = match body.get("client_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "client_id required"})),
            )
                .into_response()
        }
    };
    let client_id = match client_id_str.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client_id UUID"})),
            )
                .into_response()
        }
    };
    if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
        return resp;
    }
    let request = crate::identity::DeviceAuthorizationRequest {
        client_id,
        scope: body
            .get("scope")
            .and_then(|v| v.as_str())
            .map(str::to_string),
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

async fn realm_register_client_dynamic(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let realm = match state.identity.get_realm(&realm_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "realm not found"})),
            )
                .into_response()
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };
    let dcr_policy = realm.config().dcr_policy.clone().unwrap_or_default();
    if !matches!(dcr_policy, crate::identity::DcrPolicy::Open) {
        return (
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": "dynamic client registration is disabled for this realm"}),
            ),
        )
            .into_response();
    }
    let client_name = body
        .get("client_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Dynamic Client")
        .to_string();
    let redirect_uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let base_slug = client_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let slug = generate_unique_slug(state.clone(), &realm_id, &base_slug).await;
    let request = crate::identity::RegisterClientRequest {
        client_name,
        redirect_uris,
        client_secret: None,
        grant_types: vec!["authorization_code".to_string()],
        require_consent: true,
        client_logo_url: None,
        slug: Some(slug),
        trust_level: crate::identity::ClientTrustLevel::ThirdParty,
        declared_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        consent_spans_orgs: false,
    };
    match state.identity.register_client(&realm_id, &request) {
        Ok(client) => {
            let resp = serde_json::json!({
                "client_id": client.client_id().to_string(),
                "client_name": client.client_name(),
                "redirect_uris": client.redirect_uris(),
                "grant_types": client.grant_types(),
            });
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Webhook management (admin) ===

/// JSON body for `POST /admin/webhooks`.
#[derive(Debug, Deserialize)]
struct CreateWebhookBody {
    url: String,
    secret: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    event_filters: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

/// JSON body for `PUT /admin/webhooks/{id}`.
#[derive(Debug, Deserialize)]
struct UpdateWebhookBody {
    url: Option<String>,
    secret: Option<String>,
    enabled: Option<bool>,
    event_filters: Option<Vec<String>>,
}

/// Query params for `GET /admin/webhooks`.
#[derive(Debug, Deserialize, Default)]
struct WebhookListParams {
    enabled_only: Option<bool>,
}

/// Query params for `GET /admin/webhooks/{id}/deliveries`.
#[derive(Debug, Deserialize, Default)]
struct DeliveryListParams {
    limit: Option<usize>,
}

fn require_webhook_engine(
    state: &AppState,
) -> Result<Arc<dyn WebhookEngine>, (StatusCode, Json<serde_json::Value>)> {
    state.webhook.clone().ok_or_else(|| {
        (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({"error": "webhooks not configured"})),
        )
    })
}

fn parse_event_filters(
    raw: &[String],
) -> Result<Vec<crate::audit::AuditAction>, (StatusCode, Json<serde_json::Value>)> {
    raw.iter()
        .map(|s| {
            s.parse::<crate::audit::AuditAction>().map_err(|_| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": format!("unknown event type: {s}")})),
                )
            })
        })
        .collect()
}

/// `GET /admin/webhooks` — list webhook subscriptions for the authenticated realm.
async fn admin_list_webhooks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<WebhookListParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    let query = WebhookQuery {
        realm_id: auth.realm_id,
        enabled_only: params.enabled_only.unwrap_or(false),
    };

    match engine.list(&query) {
        Ok(subs) => (
            StatusCode::OK,
            Json(serde_json::json!({ "webhooks": subs })),
        )
            .into_response(),
        Err(e) => {
            error!("list webhooks failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "list webhooks failed"})),
            )
                .into_response()
        }
    }
}

/// `POST /admin/webhooks` — create a webhook subscription.
async fn admin_create_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateWebhookBody>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    let event_filters = match parse_event_filters(&body.event_filters) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };

    let req = CreateWebhookRequest {
        realm_id: auth.realm_id,
        url: body.url,
        secret: body.secret,
        enabled: body.enabled,
        event_filters,
    };

    match engine.create(&req) {
        Ok(sub) => (StatusCode::CREATED, Json(sub)).into_response(),
        Err(crate::webhook::WebhookError::InvalidUrl { reason }) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": reason})),
        )
            .into_response(),
        Err(crate::webhook::WebhookError::SecretTooShort) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "secret must be at least 16 bytes"})),
        )
            .into_response(),
        Err(e) => {
            error!("create webhook failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "create webhook failed"})),
            )
                .into_response()
        }
    }
}

/// `GET /admin/webhooks/{id}` — fetch a single webhook subscription.
async fn admin_get_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let webhook_id = match parse_webhook_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    match engine.get(&auth.realm_id, &webhook_id) {
        Ok(sub) => (StatusCode::OK, Json(sub)).into_response(),
        Err(crate::webhook::WebhookError::NotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "webhook not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("get webhook failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "get webhook failed"})),
            )
                .into_response()
        }
    }
}

/// `PUT /admin/webhooks/{id}` — update a webhook subscription.
async fn admin_update_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateWebhookBody>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let webhook_id = match parse_webhook_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let event_filters = match body.event_filters.as_deref() {
        Some(raw) => match parse_event_filters(raw) {
            Ok(f) => Some(f),
            Err(e) => return e.into_response(),
        },
        None => None,
    };

    let req = UpdateWebhookRequest {
        url: body.url,
        secret: body.secret,
        enabled: body.enabled,
        event_filters,
    };

    match engine.update(&auth.realm_id, &webhook_id, &req) {
        Ok(sub) => (StatusCode::OK, Json(sub)).into_response(),
        Err(crate::webhook::WebhookError::NotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "webhook not found"})),
        )
            .into_response(),
        Err(crate::webhook::WebhookError::InvalidUrl { reason }) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": reason})),
        )
            .into_response(),
        Err(crate::webhook::WebhookError::SecretTooShort) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "secret must be at least 16 bytes"})),
        )
            .into_response(),
        Err(e) => {
            error!("update webhook failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "update webhook failed"})),
            )
                .into_response()
        }
    }
}

/// `DELETE /admin/webhooks/{id}` — delete a webhook subscription.
async fn admin_delete_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let webhook_id = match parse_webhook_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    match engine.delete(&auth.realm_id, &webhook_id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(crate::webhook::WebhookError::NotFound { .. }) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "webhook not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("delete webhook failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "delete webhook failed"})),
            )
                .into_response()
        }
    }
}

/// `GET /admin/webhooks/{id}/deliveries` — list delivery log for a subscription.
async fn admin_list_webhook_deliveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(params): Query<DeliveryListParams>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let engine = match require_webhook_engine(&state) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let webhook_id = match parse_webhook_id(&id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let query = DeliveryQuery {
        realm_id: auth.realm_id,
        webhook_id: Some(webhook_id),
        limit: Some(params.limit.unwrap_or(50).min(200)),
    };

    match engine.list_deliveries(&query) {
        Ok(deliveries) => (
            StatusCode::OK,
            Json(serde_json::json!({ "deliveries": deliveries })),
        )
            .into_response(),
        Err(e) => {
            error!("list webhook deliveries failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "list deliveries failed"})),
            )
                .into_response()
        }
    }
}

fn parse_webhook_id(s: &str) -> Result<WebhookId, (StatusCode, Json<serde_json::Value>)> {
    // IDs arrive either as bare UUIDs or as "wh_{uuid}" — strip the prefix.
    let uuid_str = s.strip_prefix("wh_").unwrap_or(s);
    uuid_str
        .parse::<uuid::Uuid>()
        .map(WebhookId::new)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid webhook id"})),
            )
        })
}

// === RP-Initiated Logout (OIDC RPL §2 + OIDC BCL §2.5) ===

/// Query parameters for `GET /end_session`.
#[derive(Debug, Deserialize, Default)]
struct EndSessionParams {
    /// ID token previously issued to the RP. Accepted even when expired.
    id_token_hint: Option<String>,
    /// Post-logout URI (must be registered on the client when `client_id` is present).
    post_logout_redirect_uri: Option<String>,
    /// Client ID — used to validate `post_logout_redirect_uri`.
    client_id: Option<String>,
    /// Opaque state — echoed to `post_logout_redirect_uri` as `?state=…`.
    state: Option<String>,
}

/// `GET /end_session` — RP-initiated logout.
///
/// Revokes the session identified by `id_token_hint`, fans out back-channel
/// logout tokens to all registered RPs, and either redirects to
/// `post_logout_redirect_uri` or renders a front-channel logout page.
///
/// All parameters are optional; when neither `id_token_hint` nor a session
/// can be inferred, the endpoint returns 400.
async fn end_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<EndSessionParams>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let client_id = params
        .client_id
        .as_deref()
        .and_then(|s| s.parse::<uuid::Uuid>().ok())
        .map(crate::core::ClientId::new);

    let request = crate::identity::oidc::RpLogoutRequest {
        id_token_hint: params.id_token_hint,
        session_id: None,
        post_logout_redirect_uri: params.post_logout_redirect_uri.clone(),
        client_id,
        state: params.state.clone(),
    };

    let result = match state.identity.initiate_logout(&realm_id, &request) {
        Ok(r) => r,
        Err(crate::identity::IdentityError::SessionNotFound) => {
            // Session already gone — still redirect cleanly.
            return end_session_redirect(params.post_logout_redirect_uri, params.state);
        }
        Err(crate::identity::IdentityError::InvalidToken) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_request", "error_description": "id_token_hint could not be parsed"})),
            )
                .into_response();
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    // Fan out back-channel logout notifications asynchronously (fire-and-forget).
    for target in result.backchannel_targets {
        tokio::spawn(async move {
            let client = HttpClient::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            let outcome = client
                .post(&target.uri)
                .form(&[("logout_token", &target.logout_token)])
                .send()
                .await;
            if let Err(e) = outcome {
                tracing::warn!(uri = %target.uri, error = %e, "backchannel logout delivery failed");
            }
        });
    }

    // Serve front-channel logout page (with iframes) or redirect directly.
    if !result.frontchannel_targets.is_empty() {
        let sid = result.session_id.as_uuid().to_string();
        let issuer_enc =
            form_urlencoded::byte_serialize(state.identity.oidc_discovery().issuer.as_bytes())
                .collect::<String>();
        let sid_enc = form_urlencoded::byte_serialize(sid.as_bytes()).collect::<String>();

        let iframes: Vec<String> = result
            .frontchannel_targets
            .iter()
            .map(|t| {
                // Append iss and sid query params per OIDC FCL spec.
                let sep = if t.uri.contains('?') { '&' } else { '?' };
                format!(
                    r#"<iframe src="{uri}{sep}iss={issuer}&sid={sid}" style="display:none;width:0;height:0;border:0"></iframe>"#,
                    uri = html_escape(&t.uri),
                    sep = sep,
                    issuer = issuer_enc,
                    sid = sid_enc,
                )
            })
            .collect();

        let redirect_meta = result
            .post_logout_redirect_uri
            .as_deref()
            .map(|uri| {
                let escaped = html_escape(uri);
                format!(r#"<meta http-equiv="refresh" content="2;url={escaped}">"#)
            })
            .unwrap_or_default();

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Signing out…</title>
{redirect_meta}
</head>
<body>
{iframes}
</body>
</html>"#,
            redirect_meta = redirect_meta,
            iframes = iframes.join("\n"),
        );

        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response();
    }

    end_session_redirect(result.post_logout_redirect_uri, result.state)
}

/// Builds the post-logout redirect response, appending `state` when present.
fn end_session_redirect(uri: Option<String>, state: Option<String>) -> Response {
    match uri {
        None => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "logged out"})),
        )
            .into_response(),
        Some(base_uri) => {
            let redirect_uri = match state {
                None => base_uri,
                Some(s) => {
                    let sep = if base_uri.contains('?') { '&' } else { '?' };
                    let state_enc =
                        form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
                    format!("{base_uri}{sep}state={state_enc}")
                }
            };
            Redirect::to(&redirect_uri).into_response()
        }
    }
}

/// HTML-escapes the five special characters to prevent XSS in inline HTML.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
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
