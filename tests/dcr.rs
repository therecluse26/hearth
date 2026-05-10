//! Integration tests for Dynamic Client Registration (RFC 7591).
//!
//! Covers `POST /register` with per-realm DCR policy gating, secret
//! generation, slug uniqueness, trust level enforcement, and response
//! shape compliance with RFC 7591 §3.2.1.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::identity::{CreateRealmRequest, DcrPolicy, RealmConfig};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

fn dcr_body(name: &str, redirects: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "client_name": name,
        "redirect_uris": redirects,
        "grant_types": ["authorization_code"]
    })
}

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

fn open_dcr_realm_config() -> RealmConfig {
    RealmConfig {
        dcr_policy: Some(DcrPolicy::Open),
        ..Default::default()
    }
}

// ===== Scenario D1: Successful DCR flow =====

#[tokio::test]
async fn dcr_creates_client_with_server_secret() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "dcr-open".to_string(),
            config: Some(open_dcr_realm_config()),
        })
        .expect("create realm");
    let realm_id = realm.id().as_uuid().to_string();

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&dcr_body("Test App", &["https://app.example.com/cb"]))
                        .unwrap(),
                ))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");

    assert!(body["client_id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(body["client_secret"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert_eq!(body["client_secret_expires_at"].as_u64().unwrap(), 0);
    assert_eq!(
        body["token_endpoint_auth_method"].as_str().unwrap(),
        "client_secret_basic"
    );
}

// ===== Scenario D2: DCR rejected when disabled =====

#[tokio::test]
async fn dcr_rejected_when_disabled() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "dcr-disabled".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().as_uuid().to_string();

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&dcr_body("App", &["https://x.example.com/cb"])).unwrap(),
                ))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
    assert!(body["error"]
        .as_str()
        .is_some_and(|s| s.contains("disabled")));
}

// ===== Scenario D3: ThirdParty trust and consent =====

#[tokio::test]
async fn dcr_sets_third_party_trust_and_consent() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "dcr-trust".to_string(),
            config: Some(open_dcr_realm_config()),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let realm_id_str = realm_id.as_uuid().to_string();

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("X-Realm-ID", &realm_id_str)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&dcr_body("Trust Check", &["https://a.example.com/cb"]))
                        .unwrap(),
                ))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
    let client_id_str = body["client_id"].as_str().unwrap();

    let client_uuid: uuid::Uuid = client_id_str.parse().expect("valid uuid");
    let client = h
        .identity()
        .get_client(&realm_id, &hearth::core::ClientId::new(client_uuid))
        .expect("get")
        .expect("found");

    assert_eq!(
        client.trust_level(),
        hearth::identity::ClientTrustLevel::ThirdParty,
        "DCR clients must have ThirdParty trust"
    );
    assert!(client.require_consent(), "DCR clients must require consent");
}

// ===== Scenario D4: Unique slug with random suffix =====

#[tokio::test]
async fn dcr_generates_unique_slug_with_random_suffix() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "dcr-slug".to_string(),
            config: Some(open_dcr_realm_config()),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let realm_id_str = realm_id.as_uuid().to_string();

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("X-Realm-ID", &realm_id_str)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&dcr_body(
                        "My Cool App",
                        &["https://app.example.com/cb"],
                    ))
                    .unwrap(),
                ))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
    let client_id_str = body["client_id"].as_str().unwrap();

    let client_uuid: uuid::Uuid = client_id_str.parse().expect("valid uuid");
    let client = h
        .identity()
        .get_client(&realm_id, &hearth::core::ClientId::new(client_uuid))
        .expect("get")
        .expect("found");

    let slug = client.slug();
    assert!(
        slug.starts_with("my-cool-app-"),
        "slug should begin with slugified name: {slug}"
    );
}

// ===== Scenario D5: Echoes grant_types with engine defaults =====

#[tokio::test]
async fn dcr_echoes_grant_types_with_engine_defaults() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "dcr-grants".to_string(),
            config: Some(open_dcr_realm_config()),
        })
        .expect("create realm");
    let realm_id_str = realm.id().as_uuid().to_string();

    let app = build_app(&h).await;

    // Send empty grant_types — engine should default to ["authorization_code"].
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("X-Realm-ID", &realm_id_str)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "client_name": "DefaultGrants",
                        "redirect_uris": ["https://x.example.com/cb"]
                    }))
                    .unwrap(),
                ))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::CREATED);

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
    let grant_types: Vec<&str> = body["grant_types"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(grant_types, vec!["authorization_code"]);
}

// ===== Scenario D6: Validates client name =====

#[tokio::test]
async fn dcr_validates_client_name() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "dcr-validate".to_string(),
            config: Some(open_dcr_realm_config()),
        })
        .expect("create realm");
    let realm_id_str = realm.id().as_uuid().to_string();

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("X-Realm-ID", &realm_id_str)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "client_name": "",
                        "redirect_uris": ["https://x.example.com/cb"]
                    }))
                    .unwrap(),
                ))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===== Scenario D7: Requires X-Realm-ID header =====

#[tokio::test]
async fn dcr_requires_x_realm_id() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&dcr_body("App", &["https://x.example.com/cb"])).unwrap(),
                ))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
    assert!(body["error"]
        .as_str()
        .is_some_and(|s| s.contains("X-Realm-ID")));
}

// ===== Scenario D8: Realm not found =====

#[tokio::test]
async fn dcr_unknown_realm_returns_404() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("X-Realm-ID", "11111111-1111-1111-1111-111111111111")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&dcr_body("App", &["https://x.example.com/cb"])).unwrap(),
                ))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
