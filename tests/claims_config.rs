//! Integration tests for `resolve_claims_for_target` and `gates_pass`.
//!
//! Exercises the layered claim-profile system:
//! - Default profile emits `roles` only for first-party clients.
//! - `required_scopes` gate uses granted_scopes (not requested).
//! - Custom overrides fall back to default when gate fails.
//! - `Omit` source suppresses the default claim.

mod common;

use std::collections::BTreeSet;

use hearth::identity::claims_config::{
    resolve_claims_for_target, ClaimEvaluationContext, ClaimMapping, ClaimSource, ClaimTarget,
};
use hearth::identity::oidc::ClientTrustLevel;
use hearth::identity::{CreateRealmRequest, CreateUserRequest, RegisterClientRequest};

fn granted(scopes: &[&str]) -> BTreeSet<String> {
    scopes.iter().map(|s| (*s).to_string()).collect()
}

// ---------------------------------------------------------------------------
// Test 1: default profile emits roles for first-party client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn default_profile_emits_roles_for_first_party() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "claims-fp-realm".to_string(),
            config: None,
        })
        .expect("realm");
    let realm_id = realm.id().clone();

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "fp-user@example.com".to_string(),
                display_name: "FP User".to_string(),
                first_name: "FP".to_string(),
                last_name: "User".to_string(),
                        attributes: Default::default(),
            },
        )
        .expect("user");

    // Create a first-party client.
    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "FirstPartyApp".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                slug: Some("fp-app".to_string()),
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: vec![],
                consent_spans_orgs: false,
            },
        )
        .expect("client");

    let ctx = ClaimEvaluationContext {
        user: &user,
        client: &client,
        roles: &["admin".to_string()],
        groups: &[],
        permissions: &[],
        granted_scopes: &granted(&["openid"]),
        oid: None,
    };

    let claims = resolve_claims_for_target(ClaimTarget::AccessToken, &[], &ctx);
    assert!(
        claims.contains_key("roles"),
        "first-party client must get 'roles' claim; got keys: {:?}",
        claims.keys().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Test 2: default profile suppresses roles for third-party client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn default_profile_suppresses_roles_for_third_party() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "claims-tp-realm".to_string(),
            config: None,
        })
        .expect("realm");
    let realm_id = realm.id().clone();

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "tp-user@example.com".to_string(),
                display_name: "TP User".to_string(),
                first_name: "TP".to_string(),
                last_name: "User".to_string(),
                        attributes: Default::default(),
            },
        )
        .expect("user");

    // Create a third-party (DCR-like) client.
    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "ThirdPartyApp".to_string(),
                redirect_uris: vec!["https://third.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                slug: Some("tp-app".to_string()),
                trust_level: ClientTrustLevel::ThirdParty,
                declared_scopes: vec![],
                consent_spans_orgs: false,
            },
        )
        .expect("client");

    let ctx = ClaimEvaluationContext {
        user: &user,
        client: &client,
        roles: &["admin".to_string()],
        groups: &[],
        permissions: &[],
        granted_scopes: &granted(&["openid"]),
        oid: None,
    };

    let claims = resolve_claims_for_target(ClaimTarget::AccessToken, &[], &ctx);
    assert!(
        !claims.contains_key("roles"),
        "third-party client must NOT get 'roles' claim; got keys: {:?}",
        claims.keys().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Test 3: required_scopes gate uses granted_scopes (not merely requested)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_scopes_gate_uses_granted_not_requested() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "claims-scope-gate-realm".to_string(),
            config: None,
        })
        .expect("realm");
    let realm_id = realm.id().clone();

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "gate-user@example.com".to_string(),
                display_name: "Gate User".to_string(),
                first_name: "Gate".to_string(),
                last_name: "User".to_string(),
                        attributes: Default::default(),
            },
        )
        .expect("user");

    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "ScopeApp".to_string(),
                redirect_uris: vec!["https://scope.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                slug: Some("scope-app".to_string()),
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: vec![],
                consent_spans_orgs: false,
            },
        )
        .expect("client");

    // Custom mapping that requires "admin" scope.
    let mapping = ClaimMapping {
        claim: "employee_id".to_string(),
        source: ClaimSource::UserAttribute {
            attribute: "employee_id".to_string(),
        },
        include_in_access_token: true,
        include_in_id_token: false,
        include_in_userinfo: false,
        first_party_only: false,
        required_scopes: Some(vec!["admin".to_string()]),
        allowed_clients: None,
    };

    // Granted scopes do NOT include "admin" — mapping must be suppressed.
    let ctx_without = ClaimEvaluationContext {
        user: &user,
        client: &client,
        roles: &[],
        groups: &[],
        permissions: &[],
        granted_scopes: &granted(&["openid"]),
        oid: None,
    };
    let claims_without =
        resolve_claims_for_target(ClaimTarget::AccessToken, &[mapping.clone()], &ctx_without);
    assert!(
        !claims_without.contains_key("employee_id"),
        "employee_id must be suppressed without 'admin' in granted_scopes"
    );

    // Granted scopes include "admin" — mapping must fire.
    let ctx_with = ClaimEvaluationContext {
        user: &user,
        client: &client,
        roles: &[],
        groups: &[],
        permissions: &[],
        granted_scopes: &granted(&["openid", "admin"]),
        oid: None,
    };
    let claims_with = resolve_claims_for_target(ClaimTarget::AccessToken, &[mapping], &ctx_with);
    // The user has no "employee_id" attribute, so value is absent (None from evaluate).
    // What matters is the gate passed — but since the attribute is missing, the
    // claim is still omitted. Add a mapping with a Constant to verify the gate:
    let const_mapping = ClaimMapping {
        claim: "dept".to_string(),
        source: ClaimSource::Constant {
            value: serde_json::Value::String("engineering".to_string()),
        },
        include_in_access_token: true,
        include_in_id_token: false,
        include_in_userinfo: false,
        first_party_only: false,
        required_scopes: Some(vec!["admin".to_string()]),
        allowed_clients: None,
    };

    let ctx_with2 = ClaimEvaluationContext {
        user: &user,
        client: &client,
        roles: &[],
        groups: &[],
        permissions: &[],
        granted_scopes: &granted(&["openid", "admin"]),
        oid: None,
    };
    let claims_const_with = resolve_claims_for_target(
        ClaimTarget::AccessToken,
        &[const_mapping.clone()],
        &ctx_with2,
    );
    assert!(
        claims_const_with.contains_key("dept"),
        "dept must appear when 'admin' is in granted_scopes"
    );

    let ctx_const_without = ClaimEvaluationContext {
        user: &user,
        client: &client,
        roles: &[],
        groups: &[],
        permissions: &[],
        granted_scopes: &granted(&["openid"]),
        oid: None,
    };
    let claims_const_without = resolve_claims_for_target(
        ClaimTarget::AccessToken,
        &[const_mapping],
        &ctx_const_without,
    );
    assert!(
        !claims_const_without.contains_key("dept"),
        "dept must be suppressed when 'admin' is absent from granted_scopes"
    );
    let _ = claims_with; // suppress unused warning
}

// ---------------------------------------------------------------------------
// Test 4: override with failing gate falls back to default mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn yaml_override_fallback_to_default_when_gate_fails() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "claims-fallback-realm".to_string(),
            config: None,
        })
        .expect("realm");
    let realm_id = realm.id().clone();

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "fallback-user@example.com".to_string(),
                display_name: "Fallback User".to_string(),
                first_name: "Fallback".to_string(),
                last_name: "User".to_string(),
                        attributes: Default::default(),
            },
        )
        .expect("user");

    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "FallbackApp".to_string(),
                redirect_uris: vec!["https://fallback.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                slug: Some("fallback-app".to_string()),
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: vec![],
                consent_spans_orgs: false,
            },
        )
        .expect("client");

    // Override for "groups" that requires scope "admin" (gate will fail).
    let override_mapping = ClaimMapping {
        claim: "groups".to_string(),
        source: ClaimSource::Constant {
            value: serde_json::Value::Array(vec![serde_json::Value::String(
                "custom-group".to_string(),
            )]),
        },
        include_in_access_token: true,
        include_in_id_token: false,
        include_in_userinfo: false,
        first_party_only: false,
        required_scopes: Some(vec!["admin".to_string()]),
        allowed_clients: None,
    };

    // Without "admin" scope, the override gate fails → default "groups" mapping wins.
    let ctx = ClaimEvaluationContext {
        user: &user,
        client: &client,
        roles: &[],
        groups: &["default-group".to_string()],
        permissions: &[],
        granted_scopes: &granted(&["openid"]),
        oid: None,
    };

    let claims = resolve_claims_for_target(ClaimTarget::AccessToken, &[override_mapping], &ctx);
    // The default groups mapping (first_party_only=true, no required_scopes) should win.
    let groups_val = claims.get("groups").expect("groups claim must be present");
    let arr = groups_val.as_array().expect("groups must be array");
    let group_strings: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        group_strings.contains(&"default-group"),
        "default groups mapping must win when override gate fails; got {groups_val:?}"
    );
    assert!(
        !group_strings.contains(&"custom-group"),
        "custom-group must not appear when override gate fails"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Omit source suppresses default claim
// ---------------------------------------------------------------------------

#[tokio::test]
async fn omit_source_suppresses_default_claim() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "claims-omit-realm".to_string(),
            config: None,
        })
        .expect("realm");
    let realm_id = realm.id().clone();

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "omit-user@example.com".to_string(),
                display_name: "Omit User".to_string(),
                first_name: "Omit".to_string(),
                last_name: "User".to_string(),
                        attributes: Default::default(),
            },
        )
        .expect("user");

    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "OmitApp".to_string(),
                redirect_uris: vec!["https://omit.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                slug: Some("omit-app".to_string()),
                trust_level: ClientTrustLevel::FirstParty,
                declared_scopes: vec![],
                consent_spans_orgs: false,
            },
        )
        .expect("client");

    // Override "roles" with Omit — should suppress the default roles claim.
    let omit_roles = ClaimMapping {
        claim: "roles".to_string(),
        source: ClaimSource::Omit,
        include_in_access_token: true,
        include_in_id_token: false,
        include_in_userinfo: false,
        first_party_only: false,
        required_scopes: None,
        allowed_clients: None,
    };

    let ctx = ClaimEvaluationContext {
        user: &user,
        client: &client,
        roles: &["admin".to_string()],
        groups: &[],
        permissions: &[],
        granted_scopes: &granted(&["openid"]),
        oid: None,
    };

    let claims = resolve_claims_for_target(ClaimTarget::AccessToken, &[omit_roles], &ctx);
    assert!(
        !claims.contains_key("roles"),
        "Omit override must suppress the default 'roles' claim; got keys: {:?}",
        claims.keys().collect::<Vec<_>>()
    );
}
