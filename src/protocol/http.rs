//! HTTP server and route definitions.
//!
//! Builds an [`axum::Router`] with health, OIDC discovery, and JWKS endpoints.
//! The server is configured with shared application state containing the
//! identity engine.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router};
use tokio::net::TcpListener;
use tracing::info;

use crate::identity::IdentityEngine;

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
