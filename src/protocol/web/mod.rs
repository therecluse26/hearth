//! Web UI protocol adapter.
//!
//! Serves the first-run onboarding and placeholder login/dashboard pages
//! under `/ui/*`. Wire adapter only — all state changes flow through the
//! Identity and Authorization engines via [`OnboardingService`].
//!
//! The UI is intentionally minimal: inline HTML, no templating engine,
//! no client-side JavaScript. The [Phase 1.6 Admin UI plan] will replace
//! these pages with askama templates + HTMX; the router and handler
//! shape stay the same.
//!
//! # Security notes
//!
//! * The setup handler is gated on a one-time token generated at startup
//!   (Jenkins-style). The token is held in `<data_dir>/.setup_token` and
//!   compared in constant time via [`crate::identity::onboarding`].
//! * Setup POST includes the token as a hidden form field — same
//!   credential as the GET, so an attacker needs the token in *both*
//!   steps.
//! * All `Set-Cookie` attributes use `HttpOnly; Path=/ui; SameSite=Lax`.
//!   TLS termination is handled one layer up; when TLS is enabled, the
//!   cookie is reissued with `Secure` added.

use std::sync::Arc;

use axum::Router;

use crate::identity::onboarding::OnboardingService;
use crate::identity::IdentityEngine;

pub mod handlers;

/// Shared state for the `/ui/*` routes.
///
/// Holds the onboarding service (used only for first-run setup) plus a
/// direct handle to the identity engine (used by verify-email and
/// login). The state is cheap to clone — each field is an `Arc`.
#[derive(Clone)]
pub struct WebState {
    /// Identity engine for session creation, password verification, and
    /// email-verification token consumption.
    pub identity: Arc<dyn IdentityEngine>,
    /// First-run onboarding orchestration.
    pub onboarding: Arc<OnboardingService>,
}

impl WebState {
    /// Builds a new `WebState`.
    #[must_use]
    pub fn new(identity: Arc<dyn IdentityEngine>, onboarding: Arc<OnboardingService>) -> Self {
        Self {
            identity,
            onboarding,
        }
    }
}

/// Builds the `/ui/*` axum router.
///
/// Routes:
///
/// | Path | Method | Description |
/// |---|---|---|
/// | `/ui/setup` | GET | First-run setup form (requires `?token=`) |
/// | `/ui/setup` | POST | Submit setup form |
/// | `/ui/setup/sent` | GET | "Check your email" confirmation |
/// | `/ui/verify-email` | GET | Consume an email-verification token |
/// | `/ui/login` | GET | Login form |
/// | `/ui/login` | POST | Submit login credentials |
/// | `/ui/` | GET | Placeholder dashboard |
pub fn router(state: WebState) -> Router {
    let ui_routes = Router::new()
        .route(
            "/setup",
            axum::routing::get(handlers::setup_form).post(handlers::setup_submit),
        )
        .route("/setup/sent", axum::routing::get(handlers::setup_sent))
        .route("/verify-email", axum::routing::get(handlers::verify_email))
        .route(
            "/login",
            axum::routing::get(handlers::login_form).post(handlers::login_submit),
        )
        .route("/", axum::routing::get(handlers::dashboard))
        .with_state(Arc::new(state));

    Router::new().nest("/ui", ui_routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke-test that the router builder is object-safe in the sense
    // that `WebState::new` compiles with the current trait object types.
    // Full HTTP-level tests live in `tests/onboarding.rs`.
    #[allow(clippy::items_after_statements)]
    #[test]
    fn web_state_builder_is_clonable() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<WebState>();
    }
}
