//! Phase 1 cross-cutting adversarial tests (Step 31).
//!
//! Global invariants applied across all Phase 1 surfaces: error messages
//! leak no internal state, sensitive types implement `ZeroizeOnDrop`,
//! and HTTP endpoints reject oversized request bodies.
//!
//! Mirrors `tests/cross_cutting.rs` — the helpers are intentionally
//! duplicated per-file so each integration test binary stays self-contained.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::authz::{AuthzConfig, AuthzError, EmbeddedAuthzEngine};
use hearth::core::{Clock, SystemClock, TenantId, UserId};
use hearth::identity::{
    CleartextPassword, CreateTenantRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityError, RecoveryCodes,
};
use hearth::protocol::http::{router, AppState};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

/// Patterns that should NEVER appear in error messages exposed by
/// Phase 1 surfaces.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "/home/",
    "/tmp/",
    "/var/",
    "stack trace",
    "backtrace",
    "thread '",
    "panicked at",
    "src/",
    ".rs:",
    "RUST_BACKTRACE",
    "SELECT ",
    "INSERT ",
    "DELETE ",
    "key:",
    "password",
    "secret",
    "BEGIN PRIVATE",
    "BEGIN RSA",
];

/// Asserts that a message contains no forbidden patterns.
fn assert_no_leaks(context: &str, msg: &str) {
    for pattern in FORBIDDEN_PATTERNS {
        assert!(
            !msg.to_lowercase().contains(&pattern.to_lowercase()),
            "{context} leaks '{pattern}' in: {msg}"
        );
    }
}

/// Compile-time check that a type implements `ZeroizeOnDrop`.
fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

/// Formats the result of an operation as its error message, or "ok".
fn err_display<T>(result: Result<T, impl std::fmt::Display>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("{e}"),
    }
}

// === TEST_SCENARIOS: Phase 1 error responses leak no internal state ===
//
// Drives live Phase 1 error surfaces (MFA, WebAuthn, magic link, cross-tenant
// token) and asserts rendered messages carry no filesystem paths, stack
// traces, SQL fragments, or credential material. Also checks Display impls
// for Phase 1-introduced `IdentityError` variants.

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn phase1_error_responses_leak_no_internal_state() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = harness
        .identity()
        .create_tenant(&CreateTenantRequest {
            name: format!("cc-phase1-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create tenant");
    let tenant_id = tenant.id().clone();

    let user = harness
        .identity()
        .create_user(
            &tenant_id,
            &CreateUserRequest {
                email: format!("cc-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Cross-cutting".to_string(),
            },
        )
        .expect("create user");

    // Live Phase 1 error surfaces.
    let live_errors = [
        // Invalid MFA code (MFA not enabled → MfaNotEnabled).
        err_display(
            harness
                .identity()
                .verify_totp(&tenant_id, user.id(), "000000"),
        ),
        // Invalid magic-link token.
        err_display(
            harness
                .identity()
                .validate_magic_link(&tenant_id, "garbage"),
        ),
        // Bad WebAuthn authentication (no pending challenge / credential).
        {
            let credential_id = [0u8; 16];
            let authenticator_data = [0u8; 32];
            let client_data_json: [u8; 0] = [];
            let signature: [u8; 0] = [];
            err_display(harness.identity().complete_webauthn_authentication(
                &tenant_id,
                &hearth::identity::CompleteAuthenticationParams {
                    credential_id: &credential_id,
                    authenticator_data: &authenticator_data,
                    client_data_json: &client_data_json,
                    signature: &signature,
                    user_handle: None,
                    origin: "https://example.com",
                },
            ))
        },
        // Cross-tenant token validation (foreign tenant).
        err_display(
            harness
                .identity()
                .validate_token(&TenantId::generate(), "fake.cross.tenant.token"),
        ),
    ];

    for msg in &live_errors {
        assert_no_leaks("Phase 1 live error", msg);
    }

    // Rendered Display impls for Phase 1-introduced variants.
    let phase1_displays = [
        format!("{}", IdentityError::MfaRequired),
        format!("{}", IdentityError::InvalidMfaCode),
        format!("{}", IdentityError::MfaNotEnabled),
        format!("{}", IdentityError::MfaAlreadyEnabled),
        format!("{}", IdentityError::MagicLinkTokenInvalid),
        format!("{}", IdentityError::WebAuthnCredentialNotFound),
        format!(
            "{}",
            IdentityError::WebAuthnRegistrationFailed {
                reason: "boom".to_string()
            }
        ),
        format!(
            "{}",
            IdentityError::WebAuthnAuthenticationFailed {
                reason: "boom".to_string()
            }
        ),
        format!(
            "{}",
            IdentityError::InvalidAttestation {
                reason: "boom".to_string()
            }
        ),
        format!(
            "{}",
            IdentityError::InvalidAssertion {
                reason: "boom".to_string()
            }
        ),
        format!("{}", IdentityError::TenantNotFound),
        format!("{}", IdentityError::DuplicateTenantName),
        format!("{}", IdentityError::TenantSuspended),
    ];
    for msg in &phase1_displays {
        assert_no_leaks("IdentityError Phase 1 variant", msg);
    }

    // AuthzError::Unauthorized — admin access denied for non-admins.
    let authz_unauthorized = format!(
        "{}",
        AuthzError::Unauthorized {
            reason: "requires admin role".to_string(),
        }
    );
    assert_no_leaks("AuthzError::Unauthorized", &authz_unauthorized);
    assert!(
        authz_unauthorized.contains("unauthorized"),
        "admin denial should be a generic unauthorized error: {authz_unauthorized}"
    );

    // Cross-tenant enumeration: get_user for a foreign tenant returns
    // Ok(None), not a tenant-specific error.
    let foreign_tenant = TenantId::generate();
    let lookup = harness
        .identity()
        .get_user(&foreign_tenant, &UserId::generate())
        .expect("cross-tenant user lookup should not leak via error");
    assert!(
        lookup.is_none(),
        "foreign tenant lookup must return None, not an identifying error"
    );
}

// === TEST_SCENARIOS: Sensitive data zeroed from memory (Phase 1 types) ===
//
// Compile-time enforcement of `ZeroizeOnDrop` on Phase 1 public surfaces.
// `TotpSecret` and `MagicLinkToken` remain `pub(crate)` — their zeroization
// is covered by in-crate unit tests. At the public boundary, `RecoveryCodes`
// is the newly-introduced sensitive container added in Step 31.2.

#[tokio::test]
async fn phase1_sensitive_types_zero_on_drop() {
    // Baseline re-assertion (documents the invariant in this file).
    assert_zeroize_on_drop::<CleartextPassword>();

    // Step 31.2 — recovery codes cross the MFA enrollment boundary in
    // plaintext exactly once, then must zero on drop.
    assert_zeroize_on_drop::<RecoveryCodes>();

    // Verify the Debug representation does not reveal code material.
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let tenant = harness
        .identity()
        .create_tenant(&CreateTenantRequest {
            name: format!("cc-zero-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create tenant");
    let user = harness
        .identity()
        .create_user(
            tenant.id(),
            &CreateUserRequest {
                email: format!("zero-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Zero".to_string(),
            },
        )
        .expect("create user");
    let enrollment = harness
        .identity()
        .enroll_totp(tenant.id(), user.id())
        .expect("enroll");

    let debug = format!("{:?}", enrollment.recovery_codes);
    for code in &enrollment.recovery_codes {
        assert!(
            !debug.contains(code),
            "RecoveryCodes Debug must not reveal plaintext codes: {debug}"
        );
    }
}

// === TEST_SCENARIOS: HTTP input size limits enforced ===
//
// Drives the router directly via `tower::ServiceExt::oneshot`, skipping
// a real TCP listener. Covers the 1 MiB default limit (on every route)
// and the 64 KiB small-endpoint limit on `/introspect` and `/revoke`.

/// Builds a Phase 1 router wired to an ephemeral storage dir.
///
/// The tempdir is intentionally leaked — the router captures `Arc<AppState>`
/// which mmaps files inside it. These tests exercise only the body-limit
/// middleware (axum rejects before any handler runs) so storage state
/// cleanup is not required.
fn build_router() -> axum::Router {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(temp_dir.path().to_path_buf());
    std::mem::forget(temp_dir);

    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
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

    let state = Arc::new(AppState::new(
        Arc::new(identity_engine),
        Arc::new(authz_engine),
        Arc::new(audit_engine),
    ));
    router(state)
}

#[tokio::test]
async fn phase1_http_rejects_oversized_body_default_limit() {
    let app = build_router();

    // 2 MiB body — double the 1 MiB default limit.
    let oversized = vec![b'x'; 2 * 1024 * 1024];
    let request = Request::builder()
        .method("POST")
        .uri("/users")
        .header("content-type", "application/json")
        .header("x-tenant-id", TenantId::generate().as_uuid().to_string())
        .body(Body::from(oversized))
        .expect("build request");

    let response = app.oneshot(request).await.expect("oneshot");
    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "2 MiB body should be rejected by DefaultBodyLimit (1 MiB)"
    );
}

#[tokio::test]
async fn phase1_http_rejects_oversized_body_small_limit_introspect() {
    let app = build_router();

    // 128 KiB body — double the 64 KiB small-endpoint limit.
    let oversized = vec![b'x'; 128 * 1024];
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/json")
        .header("x-tenant-id", TenantId::generate().as_uuid().to_string())
        .body(Body::from(oversized))
        .expect("build request");

    let response = app.oneshot(request).await.expect("oneshot");
    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "128 KiB body should be rejected by /introspect small limit (64 KiB)"
    );
}

#[tokio::test]
async fn phase1_http_rejects_oversized_body_small_limit_revoke() {
    let app = build_router();

    // 128 KiB body — double the 64 KiB small-endpoint limit.
    let oversized = vec![b'x'; 128 * 1024];
    let request = Request::builder()
        .method("POST")
        .uri("/revoke")
        .header("content-type", "application/json")
        .header("x-tenant-id", TenantId::generate().as_uuid().to_string())
        .body(Body::from(oversized))
        .expect("build request");

    let response = app.oneshot(request).await.expect("oneshot");
    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "128 KiB body should be rejected by /revoke small limit (64 KiB)"
    );
}
