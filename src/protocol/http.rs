//! HTTP server and route definitions.
//!
//! Builds an [`axum::Router`] with health, OIDC discovery, JWKS, and OAuth 2.0
//! endpoints. The server is configured with shared application state containing
//! the identity engine.
//!
//! The protocol layer is a thin, stateless adapter: it translates HTTP requests
//! into domain calls on `IdentityEngine` and maps `IdentityError` to HTTP
//! status codes. No business logic lives here.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Json, Router};
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::info;

use crate::core::{ClientId, TenantId, UserId};
use crate::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateUserRequest, IdentityEngine,
    RegisterClientRequest, TokenExchangeRequest,
};

/// Shared application state passed to all route handlers.
pub struct AppState {
    /// The identity engine for all domain operations.
    pub identity: Arc<dyn IdentityEngine>,
}

/// Builds the HTTP router with all configured routes.
///
/// The returned router is ready to be served with [`serve`].
pub fn router(state: Arc<AppState>) -> Router {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::SystemClock;
    use crate::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    /// Creates a test app state with an embedded engine in a temp directory.
    fn test_state(temp_dir: &std::path::Path) -> Arc<AppState> {
        let config = StorageConfig::dev(temp_dir.to_path_buf());
        let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
        let clock = Arc::new(SystemClock) as Arc<dyn crate::core::Clock>;
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let identity_engine = EmbeddedIdentityEngine::new(
            engine as Arc<dyn crate::storage::StorageEngine>,
            clock,
            identity_config,
        )
        .expect("identity engine");

        Arc::new(AppState {
            identity: Arc::new(identity_engine),
        })
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
