//! Integration tests for machine-readable error codes (HEA-490).
//!
//! Verifies that key error paths in the REST API return the correct `error_code`
//! string in the JSON response body, and that 5xx errors produce `null`.

mod common;

use std::sync::Arc;

use hearth::identity::IdentityEngine;
use hearth::protocol::http::{router, AppState};
use serde_json::Value;
use tokio::net::TcpListener;

// ─── in-process server helpers ───────────────────────────────────────────────

/// Starts an in-process axum server on a random port.
///
/// Returns the base URL, a reference to the live identity engine (so tests can
/// manipulate state directly), and a shutdown handle (drop to stop the server).
async fn start_server() -> (
    String,
    Arc<dyn IdentityEngine>,
    tokio::sync::oneshot::Sender<()>,
) {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");

    let identity = harness.identity_arc();

    let state = Arc::new(AppState::new_dev(
        Arc::clone(&identity),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let port = listener.local_addr().expect("local addr").port();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        // Keep the harness alive for the duration of the server.
        let _harness = harness;
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await
            .ok();
    });

    (format!("http://127.0.0.1:{port}"), identity, tx)
}

/// Bootstraps a dev realm and returns `(realm_id, admin_access_token)`.
async fn bootstrap(base: &str) -> (String, String) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/admin/bootstrap"))
        .send()
        .await
        .expect("bootstrap")
        .json::<Value>()
        .await
        .expect("parse bootstrap");

    let realm_id = resp["realm_id"].as_str().expect("realm_id").to_string();
    let token = resp["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    (realm_id, token)
}

// ─── Scenario 1: invalid authorization code → HEARTH_INVALID_GRANT ───────────

/// Exchanging a garbage authorization code must return `HEARTH_INVALID_GRANT`.
///
/// Covers: IdentityError::InvalidAuthorizationCode (and InvalidGrant) mapping.
#[tokio::test]
async fn token_exchange_bad_code_returns_invalid_grant_code() {
    let (base, _identity, _shutdown) = start_server().await;
    let (realm_id, _) = bootstrap(&base).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/token"))
        .header("X-Realm-ID", &realm_id)
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "code": "not-a-real-code",
            "redirect_uri": "https://example.com/cb",
            "client_id": uuid::Uuid::new_v4().to_string()
        }))
        .send()
        .await
        .expect("token exchange");

    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json().await.expect("parse body");
    assert_eq!(
        body["error_code"].as_str(),
        Some("HEARTH_INVALID_GRANT"),
        "expected HEARTH_INVALID_GRANT, got: {body}"
    );
    assert!(
        body["error"].as_str().is_some(),
        "error field must be present"
    );
}

// ─── Scenario 2: duplicate email → HEARTH_DUPLICATE_EMAIL ────────────────────

/// Creating two users with the same email must return `HEARTH_DUPLICATE_EMAIL`
/// on the second attempt.
///
/// Covers: IdentityError::DuplicateEmail mapping.
#[tokio::test]
async fn admin_create_user_duplicate_email_returns_error_code() {
    let (base, _identity, _shutdown) = start_server().await;
    let (realm_id, token) = bootstrap(&base).await;

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "email": "dup@example.com",
        "display_name": "Dup Test"
    });

    let first = client
        .post(format!("{base}/admin/users"))
        .header("X-Realm-ID", &realm_id)
        .header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .expect("first create");
    assert_eq!(first.status().as_u16(), 201, "first create must succeed");

    let second = client
        .post(format!("{base}/admin/users"))
        .header("X-Realm-ID", &realm_id)
        .header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .expect("duplicate create");

    assert_eq!(second.status().as_u16(), 409);
    let second_body: Value = second.json().await.expect("parse body");
    assert_eq!(
        second_body["error_code"].as_str(),
        Some("HEARTH_DUPLICATE_EMAIL"),
        "expected HEARTH_DUPLICATE_EMAIL, got: {second_body}"
    );
    assert!(
        second_body["error"].as_str().is_some(),
        "error field must be present"
    );
}

// ─── Scenario 3: unknown OAuth client → HEARTH_INVALID_CLIENT ────────────────

/// Requesting a client_credentials token for an unregistered client must return
/// `HEARTH_INVALID_CLIENT`.
///
/// Covers: IdentityError::InvalidClient mapping.
#[tokio::test]
async fn client_credentials_unknown_client_returns_error_code() {
    let (base, _identity, _shutdown) = start_server().await;
    let (realm_id, _) = bootstrap(&base).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/token"))
        .header("X-Realm-ID", &realm_id)
        .json(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": uuid::Uuid::new_v4().to_string(),
            "client_secret": "not-a-real-secret"
        }))
        .send()
        .await
        .expect("client credentials request");

    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json().await.expect("parse body");
    assert_eq!(
        body["error_code"].as_str(),
        Some("HEARTH_INVALID_CLIENT"),
        "expected HEARTH_INVALID_CLIENT, got: {body}"
    );
    assert!(
        body["error"].as_str().is_some(),
        "error field must be present"
    );
}

// ─── Scenario 4: error_code field is always present ──────────────────────────

/// Every error response must include the `error_code` field (even if null).
/// Tests the overall JSON shape — `error` must always be a string.
#[tokio::test]
async fn error_response_always_contains_error_code_field() {
    let (base, _identity, _shutdown) = start_server().await;
    let (realm_id, _) = bootstrap(&base).await;

    // Trigger HEARTH_INVALID_GRANT which goes through identity_error_to_response
    let resp = reqwest::Client::new()
        .post(format!("{base}/token"))
        .header("X-Realm-ID", &realm_id)
        .json(&serde_json::json!({
            "grant_type": "authorization_code",
            "code": "bad-code",
            "redirect_uri": "https://example.com",
            "client_id": uuid::Uuid::new_v4().to_string()
        }))
        .send()
        .await
        .expect("request");

    let body: Value = resp.json().await.expect("parse body");
    assert!(
        body.get("error_code").is_some(),
        "error_code field must always be present (got: {body})"
    );
    assert!(
        body.get("error").is_some(),
        "error field must always be present (got: {body})"
    );
}

// ─── Scenario 5: unsupported grant type → HEARTH_UNSUPPORTED_GRANT_TYPE ──────

/// Requesting an unsupported grant type must return `HEARTH_UNSUPPORTED_GRANT_TYPE`.
///
/// Covers: IdentityError::UnsupportedGrantType mapping.
#[tokio::test]
async fn token_exchange_unknown_grant_type_returns_error_code() {
    let (base, _identity, _shutdown) = start_server().await;
    let (realm_id, _) = bootstrap(&base).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/token"))
        .header("X-Realm-ID", &realm_id)
        .json(&serde_json::json!({
            "grant_type": "urn:example:unsupported_grant",
            "client_id": uuid::Uuid::new_v4().to_string(),
            "code": "whatever"
        }))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json().await.expect("parse body");
    assert_eq!(
        body["error_code"].as_str(),
        Some("HEARTH_UNSUPPORTED_GRANT_TYPE"),
        "expected HEARTH_UNSUPPORTED_GRANT_TYPE, got: {body}"
    );
}
