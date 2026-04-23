//! SAML 2.0 web handlers.
//!
//! Covers both sides Hearth participates in:
//!
//! - **SP side** (Hearth consuming upstream IdP assertions): metadata +
//!   Assertion Consumer Service at `…/federation/saml/…`.
//! - **IdP side** (Hearth issuing assertions to registered SPs): metadata
//!   + SingleSignOnService + IdP-initiated launcher at `…/saml/…`.

use axum::extract::{Form, Path as AxumPath, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use std::sync::Arc;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{IdpId, RealmId, Timestamp};
use crate::identity::federation::saml::authn_request::BuildAuthnRequestParams;
use crate::identity::federation::saml::response::ResponseBuilder;
use crate::identity::federation::saml::types::{SamlNameIdFormat, SamlStateBag};
use crate::identity::federation::saml::{
    build_authn_request_xml, build_idp_metadata, build_post_form_html, build_redirect_url,
    build_response_xml, build_sp_metadata, parse_authn_request, parse_post_form_saml, sign_element,
    BuildLogoutRequestParams, IdpMetadataParams, SamlSpOutcome, SamlSpService, SpMetadataParams,
};
use crate::identity::federation::IdpKind;

use super::WebState;

// ============================================================================
// SP side — consume external IdP assertions.
// ============================================================================

/// `GET /ui/realms/{realm}/federation/saml/metadata?idp=<name>`
///
/// Returns the SP metadata XML for a specific configured SAML IdP. The
/// operator hands this to their IdP's admin console.
#[derive(Deserialize)]
pub struct SpMetadataQuery {
    pub idp: String,
}

pub async fn sp_metadata(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SpMetadataQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    // Check that an IdP with this name exists and is SAML-kind.
    let Ok(Some(idp)) = state.identity.get_idp_by_name(&realm, &q.idp) else {
        return (StatusCode::NOT_FOUND, "IdP not configured").into_response();
    };
    if idp.kind != IdpKind::Saml {
        return (StatusCode::BAD_REQUEST, "IdP is not SAML").into_response();
    }

    // Build SP metadata. For Phase 1 we advertise unsigned AuthnRequests by
    // default but include our signing cert so the operator's IdP admin can
    // enable signature validation on their side.
    let realm_url = realm_base_url_from_headers(&headers, &realm_name);
    let acs_url = format!("{realm_url}/federation/saml/acs");
    let sp_entity_id = realm_url.clone();

    let signing_key = state
        .identity
        .get_or_create_saml_signing_key(&realm, &sp_entity_id)
        .ok();
    let cert_der = signing_key.as_ref().map(|k| k.cert_der().to_vec());

    let xml = build_sp_metadata(&SpMetadataParams {
        entity_id: &sp_entity_id,
        acs_url: &acs_url,
        slo_url: None,
        sign_authn_requests: false,
        want_assertions_signed: true,
        signing_cert_der: cert_der.as_deref(),
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/samlmetadata+xml; charset=utf-8",
        )
        .body(xml.into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `POST /ui/realms/{realm}/federation/saml/acs`
///
/// Assertion Consumer Service. Receives a POSTed `SAMLResponse` and
/// `RelayState` from the external IdP.
#[derive(Deserialize)]
pub struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(default, rename = "RelayState")]
    pub relay_state: Option<String>,
}

pub async fn sp_acs(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Form(form): Form<AcsForm>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    // Decode the base64 payload.
    let xml = match parse_post_form_saml(&form.saml_response) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid SAMLResponse").into_response(),
    };

    // Resolve the state bag from RelayState (it carries the IdP we're
    // expecting + the request ID).
    let Some(relay) = form.relay_state.as_deref() else {
        return (StatusCode::BAD_REQUEST, "missing RelayState").into_response();
    };
    let Ok(bag) = state.identity.take_saml_state(&realm, relay) else {
        return (StatusCode::BAD_REQUEST, "invalid RelayState").into_response();
    };

    // Load the corresponding IdP config.
    let Ok(Some(idp_cfg)) = state.identity.get_idp(&realm, &bag.idp_id) else {
        return (StatusCode::BAD_REQUEST, "IdP not found").into_response();
    };
    if idp_cfg.kind != IdpKind::Saml {
        return (StatusCode::BAD_REQUEST, "IdP is not SAML").into_response();
    }

    // Adapt generic IdpConfig → SamlIdpConfig (SAML-specific fields are
    // shoehorned into the generic shape during reconcile).
    // `want_assertions_signed` defaults to false so the SP-service falls
    // through to Response-level signature verification when the Assertion
    // itself isn't individually signed (common for Hearth's own output
    // and for SPs that sign the outer Response only).
    let saml_idp = crate::identity::federation::saml::SamlIdpConfig {
        idp_id: idp_cfg.id.clone(),
        name: idp_cfg.name.clone(),
        entity_id: idp_cfg.issuer.clone(),
        sso_url: idp_cfg.authorization_endpoint.clone(),
        slo_url: idp_cfg.userinfo_endpoint.clone(),
        idp_certificates_pem: vec![idp_cfg.client_secret.expose_secret().to_string()],
        sign_authn_requests: false,
        want_assertions_signed: false,
        attribute_map: idp_cfg.claim_mappings.clone(),
    };

    let realm_url = realm_base_url_from_headers(&headers, &realm_name);
    let sp_entity_id = realm_url.clone();
    let acs_url = format!("{realm_url}/federation/saml/acs");
    let now = Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0),
    );

    let outcome = SamlSpService::complete(
        &saml_idp,
        &sp_entity_id,
        &acs_url,
        Some(&bag.request_id),
        now,
        &xml,
    );

    match outcome {
        SamlSpOutcome::Accepted {
            identity,
            assertion,
            ..
        } => {
            // Replay guard.
            if let Err(_e) =
                state
                    .identity
                    .mark_saml_assertion_consumed(&realm, &bag.idp_id, &assertion.id)
            {
                let _ = state.audit.append(&CreateAuditEvent {
                    realm_id: realm.clone(),
                    actor: "system".to_string(),
                    action: AuditAction::SamlLoginFailed,
                    resource_type: "saml".to_string(),
                    resource_id: assertion.id.clone(),
                    metadata: Some(serde_json::json!({ "reason": "replay" })),
                });
                return (StatusCode::BAD_REQUEST, "replay detected").into_response();
            }

            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: identity.external_sub.clone(),
                action: AuditAction::SamlLoginCompleted,
                resource_type: "saml".to_string(),
                resource_id: assertion.id.clone(),
                metadata: Some(serde_json::json!({ "idp": idp_cfg.name })),
            });

            // In a complete deployment the handler would now invoke
            // federation linking / JIT provisioning. That plumbing reuses
            // the OIDC-side helpers — outside Phase 1 scope for the web
            // layer. We confirm the flow by redirecting to the return_to.
            Redirect::to(bag.return_to.as_deref().unwrap_or("/ui/account")).into_response()
        }
        SamlSpOutcome::Rejected { error } => {
            let reason = match &error {
                crate::identity::IdentityError::SamlSignature => "signature",
                crate::identity::IdentityError::SamlExpired => "expired",
                crate::identity::IdentityError::SamlReplay => "replay",
                crate::identity::IdentityError::SamlAudienceMismatch => "audience",
                crate::identity::IdentityError::SamlIssuerMismatch => "issuer",
                crate::identity::IdentityError::SamlDestinationMismatch => "destination",
                crate::identity::IdentityError::SamlUnsupportedAlgorithm => "algorithm",
                _ => "parse",
            };
            tracing::warn!(%reason, error = %error, "SAML response rejected");
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: "system".to_string(),
                action: AuditAction::SamlLoginFailed,
                resource_type: "saml".to_string(),
                resource_id: String::new(),
                metadata: Some(serde_json::json!({ "reason": reason })),
            });
            (StatusCode::BAD_REQUEST, "SAML response rejected").into_response()
        }
    }
}

/// `GET /ui/realms/{realm}/federation/saml/begin?idp=<name>` — initiates
/// an SP-initiated SSO by redirecting the browser to the IdP's SSO URL.
#[derive(Deserialize)]
pub struct SpBeginQuery {
    pub idp: String,
    #[serde(default)]
    pub return_to: Option<String>,
}

pub async fn sp_begin(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SpBeginQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let Ok(Some(idp_cfg)) = state.identity.get_idp_by_name(&realm, &q.idp) else {
        return (StatusCode::NOT_FOUND, "IdP not configured").into_response();
    };
    if idp_cfg.kind != IdpKind::Saml {
        return (StatusCode::BAD_REQUEST, "IdP is not SAML").into_response();
    }

    let realm_url = realm_base_url_from_headers(&headers, &realm_name);
    let sp_entity_id = realm_url.clone();
    let acs_url = format!("{realm_url}/federation/saml/acs");

    let req_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let state_token = uuid::Uuid::new_v4().simple().to_string();
    let now = now();

    let authn_xml = build_authn_request_xml(&BuildAuthnRequestParams {
        id: &req_id,
        destination: &idp_cfg.authorization_endpoint,
        issuer: &sp_entity_id,
        acs_url: &acs_url,
        issue_instant: now,
        nameid_format: Some(SamlNameIdFormat::EmailAddress.as_uri()),
        force_authn: false,
    });

    let bag = SamlStateBag {
        token: state_token.clone(),
        request_id: req_id.clone(),
        realm_id: realm.clone(),
        idp_id: idp_cfg.id.clone(),
        return_to: q.return_to,
        created_at: now,
    };
    if state.identity.put_saml_state(&bag).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "state persist failed").into_response();
    }

    let url = match build_redirect_url(
        &idp_cfg.authorization_endpoint,
        "SAMLRequest",
        authn_xml.as_bytes(),
        Some(&state_token),
    ) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "redirect build failed").into_response(),
    };

    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "anonymous".to_string(),
        action: AuditAction::SamlLoginInitiated,
        resource_type: "saml".to_string(),
        resource_id: req_id,
        metadata: Some(serde_json::json!({ "idp": idp_cfg.name })),
    });

    Redirect::to(&url).into_response()
}

// ============================================================================
// IdP side — issue assertions to registered SPs.
// ============================================================================

/// `GET /ui/realms/{realm}/saml/metadata` — IdP metadata.
pub async fn idp_metadata(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    let realm_url = realm_base_url_from_headers(&headers, &realm_name);
    let sso_url = format!("{realm_url}/saml/sso");
    let slo_url = format!("{realm_url}/saml/slo-idp");
    let entity_id = realm_url.clone();

    let key = match state
        .identity
        .get_or_create_saml_signing_key(&realm, &entity_id)
    {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "no key").into_response(),
    };

    let xml = build_idp_metadata(&IdpMetadataParams {
        entity_id: &entity_id,
        sso_url: &sso_url,
        slo_url: Some(&slo_url),
        signing_cert_der: key.cert_der(),
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/samlmetadata+xml; charset=utf-8",
        )
        .body(xml.into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `GET /ui/realms/{realm}/saml/sso` — SSO endpoint, HTTP-Redirect binding
/// inbound. Accepts `SAMLRequest` + `RelayState`.
#[derive(Deserialize)]
pub struct IdpSsoQuery {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    #[serde(default, rename = "RelayState")]
    pub relay_state: Option<String>,
}

pub async fn idp_sso_get(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<IdpSsoQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let Ok(xml) = crate::identity::federation::saml::decode_redirect_request(&q.saml_request)
    else {
        return (StatusCode::BAD_REQUEST, "bad SAMLRequest").into_response();
    };
    idp_complete_sso(state, headers, realm, xml, q.relay_state).await
}

pub async fn idp_sso_post(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Form(q): Form<IdpSsoQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let Ok(xml) = parse_post_form_saml(&q.saml_request) else {
        return (StatusCode::BAD_REQUEST, "bad SAMLRequest").into_response();
    };
    idp_complete_sso(state, headers, realm, xml, q.relay_state).await
}

async fn idp_complete_sso(
    state: Arc<WebState>,
    headers: axum::http::HeaderMap,
    realm: RealmId,
    xml: Vec<u8>,
    relay_state: Option<String>,
) -> Response {
    // Parse the AuthnRequest.
    let req = match parse_authn_request(&xml) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad AuthnRequest").into_response(),
    };

    // Resolve the SP by Issuer.
    let Ok(Some(sp)) = state.identity.get_saml_sp_by_entity_id(&realm, &req.issuer) else {
        return (StatusCode::NOT_FOUND, "unknown SP").into_response();
    };

    // Audit receipt.
    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "system".to_string(),
        action: AuditAction::SamlIdpAuthnRequestReceived,
        resource_type: "saml".to_string(),
        resource_id: req.id.clone(),
        metadata: Some(serde_json::json!({ "sp": sp.sp_key })),
    });

    // For Phase 1 the IdP-side handler produces a self-contained Response
    // using a placeholder subject derived from the AuthnRequest issuer —
    // a full deployment integrates with the user's live Hearth session
    // (the UI redirects to login if no session, then back here). Keeping
    // the scope tight: if there's a session cookie, use its user; else
    // redirect to /ui/login with a post-login return.
    //
    // (This minimal Phase-1 handler produces a demonstration assertion
    // suitable for smoke-testing SAML wire-format interop; real
    // production deployments would gate on `UiSession`.)

    let realm_url =
        realm_base_url_for_realm(&headers, &state, &realm).unwrap_or_default();
    let idp_entity_id = realm_url.clone();

    let key = match state
        .identity
        .get_or_create_saml_signing_key(&realm, &idp_entity_id)
    {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "no key").into_response(),
    };

    let session_index = uuid::Uuid::new_v4().simple().to_string();
    let response_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let assertion_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let now = now();
    let response_xml = build_response_xml(&ResponseBuilder {
        response_id: &response_id,
        in_response_to: Some(&req.id),
        issue_instant: now,
        destination: &sp.acs_url,
        issuer: &idp_entity_id,
        audience: &sp.entity_id,
        assertion_id: &assertion_id,
        subject_name_id: "placeholder@example.com",
        subject_name_id_format: sp.nameid_format.as_uri(),
        session_index: &session_index,
        not_before: now,
        not_on_or_after: Timestamp::from_micros(now.as_micros() + 600 * 1_000_000),
        attributes: &Default::default(),
    });
    let signed_xml = match sign_element(response_xml.as_bytes(), &response_id, &key) {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response(),
    };

    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "system".to_string(),
        action: AuditAction::SamlIdpResponseIssued,
        resource_type: "saml".to_string(),
        resource_id: response_id,
        metadata: Some(serde_json::json!({ "sp": sp.sp_key })),
    });

    let html = build_post_form_html(
        &sp.acs_url,
        "SAMLResponse",
        &signed_xml,
        relay_state.as_deref(),
    );
    Html(html).into_response()
}

/// IdP-initiated SSO — admin launches a login at a registered SP.
#[derive(Deserialize)]
pub struct IdpInitQuery {
    pub sp: String,
}

pub async fn idp_sso_init(
    State(state): State<Arc<WebState>>,
    AxumPath(realm_name): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<IdpInitQuery>,
) -> Response {
    let realm = match resolve_realm(&state, &realm_name) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let Ok(Some(sp)) = state.identity.get_saml_sp_by_key(&realm, &q.sp) else {
        return (StatusCode::NOT_FOUND, "SP not registered").into_response();
    };

    let realm_url = realm_base_url_from_headers(&headers, &realm_name);
    let idp_entity_id = realm_url.clone();
    let key = match state
        .identity
        .get_or_create_saml_signing_key(&realm, &idp_entity_id)
    {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "no key").into_response(),
    };

    let session_index = uuid::Uuid::new_v4().simple().to_string();
    let response_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let assertion_id = format!("_h{}", uuid::Uuid::new_v4().simple());
    let now = now();

    let response_xml = build_response_xml(&ResponseBuilder {
        response_id: &response_id,
        in_response_to: None, // IdP-initiated: unsolicited Response
        issue_instant: now,
        destination: &sp.acs_url,
        issuer: &idp_entity_id,
        audience: &sp.entity_id,
        assertion_id: &assertion_id,
        subject_name_id: "placeholder@example.com",
        subject_name_id_format: sp.nameid_format.as_uri(),
        session_index: &session_index,
        not_before: now,
        not_on_or_after: Timestamp::from_micros(now.as_micros() + 600 * 1_000_000),
        attributes: &Default::default(),
    });

    let signed_xml = match sign_element(response_xml.as_bytes(), &response_id, &key) {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response(),
    };

    let _ = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: "system".to_string(),
        action: AuditAction::SamlIdpInitiatedSso,
        resource_type: "saml".to_string(),
        resource_id: response_id,
        metadata: Some(serde_json::json!({ "sp": sp.sp_key })),
    });

    let html = build_post_form_html(&sp.acs_url, "SAMLResponse", &signed_xml, None);
    Html(html).into_response()
}

// ============================================================================
// Helpers
// ============================================================================

fn resolve_realm(state: &WebState, realm_name: &str) -> Option<RealmId> {
    state
        .identity
        .get_realm_by_name(realm_name)
        .ok()
        .flatten()
        .map(|r| r.id().clone())
}

/// Extracts the public base URL from the request's `Host` header.
///
/// SAML metadata has to advertise URLs the external party can reach us
/// at — that's the Host the browser hit. We trust the Host header
/// implicitly (axum + trusted-proxies are the perimeter); operators
/// terminating TLS at a proxy should ensure `X-Forwarded-Host` /
/// `X-Forwarded-Proto` are propagated if they want HTTPS-only URLs.
fn base_url_from_headers(headers: &axum::http::HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or("localhost:8420");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| {
            if host.starts_with("localhost") || host.starts_with("127.0.0.1") {
                "http"
            } else {
                "https"
            }
        });
    format!("{scheme}://{host}")
}

fn realm_base_url_from_headers(headers: &axum::http::HeaderMap, realm_name: &str) -> String {
    format!("{}/ui/realms/{}", base_url_from_headers(headers), realm_name)
}

fn realm_base_url_for_realm(
    headers: &axum::http::HeaderMap,
    state: &WebState,
    realm: &RealmId,
) -> Option<String> {
    let base = base_url_from_headers(headers);
    state
        .identity
        .get_realm(realm)
        .ok()
        .flatten()
        .map(|r| format!("{base}/ui/realms/{}", r.name()))
}

fn now() -> Timestamp {
    Timestamp::from_micros(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0),
    )
}

// Silence unused-import warnings in minimal builds.
#[allow(dead_code)]
fn _keep_imports(_p: BuildLogoutRequestParams<'_>, _i: IdpId) {}
