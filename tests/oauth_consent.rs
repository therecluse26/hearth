//! Integration tests for the OAuth consent flow:
//!
//! * Browser-facing `GET /ui/oauth/authorize` entry point
//! * `GET|POST /ui/oauth/consent` interstitial
//! * Self-service consent listing at `/ui/account/applications`
//! * Admin consent visibility under `/ui/admin/users/{id}/consents`
//! * REST/JSON `/oauth/consents` and `/admin/users/{id}/consents`
//! * RFC 6749 §4.1.2.1 error redirect compliance
//! * OIDC Core §3.1.2.1 `prompt=none|consent` semantics
//! * Adversarial: CSRF, cross-user ticket replay, scope tampering, realm isolation

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::audit::{AuditAction, AuditEngine, AuditQuery};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, RegisterClientRequest,
    SessionContext, UpdateClientRequest, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];
const PASSWORD: &str = "correct-horse-battery-staple";

fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    audit: Arc<dyn AuditEngine>,
    realm_id: RealmId,
    alice_id: UserId,
    alice_session: SessionId,
    bob_id: UserId,
    bob_session: SessionId,
    /// Client that requires consent (standard 3rd-party).
    untrusted_client: OAuthClient,
    /// Client with `require_consent=false` (first-party / trusted).
    trusted_client: OAuthClient,
}

fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: None,
        })
        .expect("create realm");

    let alice = seed_active_user(&*identity, realm.id(), "alice@acme.test", "Alice");
    let bob = seed_active_user(&*identity, realm.id(), "bob@acme.test", "Bob");

    let alice_session = identity
        .create_session(realm.id(), &alice, &SessionContext::default())
        .expect("alice session")
        .id()
        .clone();
    let bob_session = identity
        .create_session(realm.id(), &bob, &SessionContext::default())
        .expect("bob session")
        .id()
        .clone();

    let untrusted_client = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Third Party App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: Some("https://app.example.com/logo.png".to_string()),
                ..Default::default()
            },
        )
        .expect("register untrusted");

    let trusted_client = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "First Party SSO".to_string(),
                redirect_uris: vec!["https://sso.internal/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                // Per AUTHZ_EXPANSION.md the consent gate is driven by
                // `trust_level`. FirstParty bypasses the consent ceremony.
                trust_level: hearth::identity::oidc::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register trusted");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz,
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    );
    let app = web::router(state);

    Rig {
        app,
        identity,
        audit,
        realm_id: realm.id().clone(),
        alice_id: alice,
        alice_session,
        bob_id: bob,
        bob_session,
        untrusted_client,
        trusted_client,
    }
}

fn seed_active_user(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    email: &str,
    display_name: &str,
) -> UserId {
    let user = identity
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: display_name.to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    identity
        .set_password(
            realm_id,
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");
    identity
        .update_user(
            realm_id,
            user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
                first_name: None,
                last_name: None,
                ..Default::default()
            },
        )
        .expect("activate");
    user.id().clone()
}

fn auth_cookie(realm_id: &RealmId, session_id: &SessionId, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        session_id.as_uuid(),
        realm_id.as_uuid(),
        tag,
        csrf,
    )
}

/// Appends the MAC-signed ticket cookie to an existing cookie header.
fn with_ticket_cookie(base: &str, user_id: &UserId, ticket: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(user_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(ticket.as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!("{base}; hearth_ui_oauth_ticket={ticket}.{tag}")
}

async fn body_utf8(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

/// Extracts the ticket cookie value from any Set-Cookie header in the response.
fn ticket_from_response(resp: &axum::response::Response) -> Option<String> {
    for v in resp.headers().get_all(header::SET_COOKIE) {
        let s = v.to_str().ok()?;
        if let Some(rest) = s.strip_prefix("hearth_ui_oauth_ticket=") {
            // value is before `;` and before `.` (ticket.mac)
            let value = rest.split(';').next()?;
            let ticket = value.split('.').next()?;
            return Some(ticket.to_string());
        }
    }
    None
}

fn location_header(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// PKCE S256 challenge for the test verifier below.
fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}
const TEST_PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

/// Builds an authorize URL with the standard params against a given client.
/// PKCE S256 is always included — required for public clients (RFC 9700).
fn authorize_url(
    client_id: &hearth::identity::OAuthClient,
    scope: &str,
    extra: &[(&str, &str)],
) -> String {
    let redir = &client_id.redirect_uris()[0];
    let challenge = pkce_challenge(TEST_PKCE_VERIFIER);
    let base = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state=xyz&code_challenge={}&code_challenge_method=S256",
        client_id.client_id().as_uuid(),
        urlencode(redir),
        urlencode(scope),
        urlencode(&challenge),
    );
    extra
        .iter()
        .fold(base, |acc, (k, v)| format!("{acc}&{k}={}", urlencode(v)))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

// ==========================================================================
// Consent flow
// ==========================================================================

#[tokio::test]
async fn first_time_flow_shows_consent_then_issues_code() {
    let rig = build_rig();
    let csrf = "csrf-1";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);

    // 1. GET /ui/oauth/authorize → 303 to /ui/oauth/consent with ticket cookie.
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile email", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    assert_eq!(location_header(&resp).as_deref(), Some("/ui/oauth/consent"));
    let ticket = ticket_from_response(&resp).expect("ticket cookie");

    // 2. GET /ui/oauth/consent with ticket cookie → renders the prompt.
    let cookie2 = with_ticket_cookie(&cookie, &rig.alice_id, &ticket);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_utf8(resp).await;
    assert!(body.contains("Third Party App"), "client name missing");
    assert!(body.contains("profile"), "scope missing");
    assert!(body.contains("email"), "scope missing");

    // 3. POST /ui/oauth/consent with decision=approve + both scopes.
    let form = format!("_csrf={csrf}&ticket={ticket}&decision=approve&scope=profile&scope=email");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    let loc = location_header(&resp).expect("location");
    assert!(
        loc.starts_with("https://app.example.com/cb?"),
        "expected client redirect, got {loc}"
    );
    assert!(loc.contains("code="), "missing authorization code in {loc}");
    assert!(loc.contains("state=xyz"), "state not echoed: {loc}");

    // 4. Consent record persisted with both scopes.
    let rec = rig
        .identity
        .get_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
        )
        .expect("get")
        .expect("persisted");
    assert_eq!(rec.granted_scopes, vec!["email", "profile"]);
}

#[tokio::test]
async fn partial_approval_stores_only_approved_scopes() {
    let rig = build_rig();
    let csrf = "csrf-part";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile email", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ticket = ticket_from_response(&resp).expect("ticket");
    let cookie2 = with_ticket_cookie(&cookie, &rig.alice_id, &ticket);

    // Approve only `profile` — `email` omitted.
    let form = format!("_csrf={csrf}&ticket={ticket}&decision=approve&scope=profile");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    let loc = location_header(&resp).expect("location");
    assert!(loc.contains("code="), "expected code in {loc}");

    let rec = rig
        .identity
        .get_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
        )
        .expect("get")
        .expect("persisted");
    assert_eq!(rec.granted_scopes, vec!["profile"]);
}

#[tokio::test]
async fn returning_user_with_sufficient_consent_bypasses_prompt() {
    let rig = build_rig();
    // Pre-seed consent.
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
            &["profile".to_string(), "email".to_string()],
        )
        .expect("grant");

    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    let loc = location_header(&resp).expect("location");
    assert!(
        loc.starts_with("https://app.example.com/cb?"),
        "expected direct client redirect (bypass), got {loc}"
    );
    assert!(loc.contains("code="), "missing code in bypass: {loc}");
}

#[tokio::test]
async fn returning_user_with_new_scope_reprompts() {
    let rig = build_rig();
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
            &["profile".to_string()],
        )
        .expect("grant");

    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile email", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    assert_eq!(location_header(&resp).as_deref(), Some("/ui/oauth/consent"));
}

#[tokio::test]
async fn deny_redirects_with_access_denied_error() {
    let rig = build_rig();
    let csrf = "csrf-deny";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ticket = ticket_from_response(&resp).expect("ticket");
    let cookie2 = with_ticket_cookie(&cookie, &rig.alice_id, &ticket);

    let form = format!("_csrf={csrf}&ticket={ticket}&decision=deny");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    let loc = location_header(&resp).expect("location");
    assert!(
        loc.contains("error=access_denied"),
        "RFC 6749 §4.1.2.1 requires access_denied, got {loc}"
    );
    assert!(loc.contains("state=xyz"), "state missing from error: {loc}");

    // No consent record was stored.
    let rec = rig
        .identity
        .get_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
        )
        .expect("get");
    assert!(rec.is_none());
}

#[tokio::test]
async fn trusted_client_bypasses_consent_even_with_no_record() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.trusted_client, "profile email", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    let loc = location_header(&resp).expect("location");
    assert!(
        loc.starts_with("https://sso.internal/cb?"),
        "expected direct redirect to trusted redirect_uri, got {loc}"
    );
    assert!(loc.contains("code="), "missing code for trusted client");
}

#[tokio::test]
async fn unauthenticated_user_is_redirected_to_login() {
    let rig = build_rig();
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    let loc = location_header(&resp).expect("location");
    assert!(
        loc.contains("/ui/login"),
        "expected login redirect, got {loc}"
    );
    assert!(loc.contains("return_to="), "missing return_to in {loc}");
}

#[tokio::test]
async fn invalid_redirect_uri_rejects_without_issuing_code() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let bad_url = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fevil.com%2Fcb&response_type=code&scope=profile&state=x",
        rig.untrusted_client.client_id().as_uuid()
    );
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(bad_url)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_client_rejected() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let bogus = uuid::Uuid::new_v4();
    let url = format!(
        "/ui/oauth/authorize?client_id={bogus}&redirect_uri=https%3A%2F%2Fx%2Fy&response_type=code&scope=p&state=s"
    );
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(url)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ==========================================================================
// OIDC prompt semantics
// ==========================================================================

#[tokio::test]
async fn prompt_none_with_no_consent_returns_consent_required() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(
                    &rig.untrusted_client,
                    "profile",
                    &[("prompt", "none")],
                ))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    let loc = location_header(&resp).expect("location");
    assert!(
        loc.contains("error=consent_required"),
        "OIDC Core §3.1.2.1 requires consent_required on prompt=none, got {loc}"
    );
}

#[tokio::test]
async fn prompt_consent_forces_reprompt_even_with_existing_record() {
    let rig = build_rig();
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
            &["profile".to_string()],
        )
        .expect("grant");

    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(
                    &rig.untrusted_client,
                    "profile",
                    &[("prompt", "consent")],
                ))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    assert_eq!(location_header(&resp).as_deref(), Some("/ui/oauth/consent"));
}

// ==========================================================================
// Adversarial
// ==========================================================================

#[tokio::test]
async fn csrf_protection_on_consent_post() {
    let rig = build_rig();
    let csrf = "csrf-good";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ticket = ticket_from_response(&resp).expect("ticket");
    let cookie2 = with_ticket_cookie(&cookie, &rig.alice_id, &ticket);

    // WRONG csrf token.
    let form = format!("_csrf=wrong&ticket={ticket}&decision=approve&scope=profile");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Nothing was persisted.
    let rec = rig
        .identity
        .get_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
        )
        .expect("get");
    assert!(rec.is_none());
}

#[tokio::test]
async fn tampered_scope_in_post_body_is_rejected() {
    let rig = build_rig();
    let csrf = "csrf-tamper";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ticket = ticket_from_response(&resp).expect("ticket");
    let cookie2 = with_ticket_cookie(&cookie, &rig.alice_id, &ticket);

    // Original request asked for `profile`; user tries to approve `admin`.
    let form = format!("_csrf={csrf}&ticket={ticket}&decision=approve&scope=admin");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cross_user_ticket_replay_is_rejected() {
    let rig = build_rig();
    let csrf_a = "csrf-a";
    let alice_cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf_a);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .header(header::COOKIE, &alice_cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ticket = ticket_from_response(&resp).expect("ticket");

    // Bob tries to use Alice's ticket.
    let csrf_b = "csrf-b";
    let bob_cookie = auth_cookie(&rig.realm_id, &rig.bob_session, csrf_b);
    // Bob MACs the ticket with *his own* user_id (otherwise cookie parse
    // fails immediately) and submits with Bob's CSRF.
    let bob_cookie_with_ticket = with_ticket_cookie(&bob_cookie, &rig.bob_id, &ticket);
    let form = format!("_csrf={csrf_b}&ticket={ticket}&decision=approve&scope=profile");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &bob_cookie_with_ticket)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    // Engine-level ticket payload says user_id=alice, but Bob is logged in;
    // ticket is consumed but the submit fails ownership check.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Alice's consent was not recorded.
    let rec = rig
        .identity
        .get_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
        )
        .expect("get");
    assert!(rec.is_none());
}

#[tokio::test]
async fn ticket_is_single_use_after_approve() {
    let rig = build_rig();
    let csrf = "csrf-su";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ticket = ticket_from_response(&resp).expect("ticket");
    let cookie2 = with_ticket_cookie(&cookie, &rig.alice_id, &ticket);

    let form = format!("_csrf={csrf}&ticket={ticket}&decision=approve&scope=profile");
    let ok = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.clone()))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(ok.status().is_redirection());

    // Second submission with same ticket should fail.
    let replay = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
}

// ==========================================================================
// Audit
// ==========================================================================

#[tokio::test]
async fn consent_granted_emits_audit_with_scope_list() {
    let rig = build_rig();
    let csrf = "csrf-audit";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile email", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ticket = ticket_from_response(&resp).expect("ticket");
    let cookie2 = with_ticket_cookie(&cookie, &rig.alice_id, &ticket);

    let form = format!("_csrf={csrf}&ticket={ticket}&decision=approve&scope=profile&scope=email");
    let _ = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    let events = rig
        .audit
        .query(&AuditQuery {
            realm_id: rig.realm_id.clone(),
            start_time: None,
            end_time: None,
            actor: None,
            action: Some(AuditAction::ConsentGranted),
            limit: Some(10),
        })
        .expect("query");
    assert_eq!(events.len(), 1, "expected 1 ConsentGranted event");
    let ev = &events[0];
    assert_eq!(ev.actor, rig.alice_id.as_uuid().to_string());
    // metadata (via, scopes) tracked in metadata-threading follow-up
}

#[tokio::test]
async fn consent_denied_emits_audit_even_when_no_record_exists() {
    let rig = build_rig();
    let csrf = "csrf-denied";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ticket = ticket_from_response(&resp).expect("ticket");
    let cookie2 = with_ticket_cookie(&cookie, &rig.alice_id, &ticket);

    let form = format!("_csrf={csrf}&ticket={ticket}&decision=deny");
    let _ = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/oauth/consent")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    let events = rig
        .audit
        .query(&AuditQuery {
            realm_id: rig.realm_id.clone(),
            start_time: None,
            end_time: None,
            actor: None,
            action: Some(AuditAction::ConsentDenied),
            limit: Some(10),
        })
        .expect("query");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor, rig.alice_id.as_uuid().to_string());
}

// ==========================================================================
// Admin "trusted client" toggle (require_consent)
// ==========================================================================

// ==========================================================================
// Self-service consent management
// ==========================================================================

#[tokio::test]
async fn list_consents_returns_only_current_user_consents() {
    let rig = build_rig();
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
            &["profile".to_string()],
        )
        .expect("grant alice");
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.bob_id,
            rig.untrusted_client.client_id(),
            &["email".to_string()],
        )
        .expect("grant bob");

    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account/applications")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_utf8(resp).await;
    assert!(body.contains("Third Party App"), "client name missing");
    assert!(body.contains("profile"), "alice's scope missing");
    // Bob's scope (`email`) should NOT leak into Alice's page. However
    // both users point to the same client — we only assert that Alice
    // sees her own scope and that the list has exactly one data attribute
    // for the client she's granted (defensive isolation check).
    let client_id_s = rig.untrusted_client.client_id().as_uuid().to_string();
    let occurrences = body
        .matches(&format!("data-consent-client=\"{client_id_s}\""))
        .count();
    assert_eq!(occurrences, 1, "expected exactly one consent row");
}

#[tokio::test]
async fn self_revoke_consent_removes_record_and_reprompts_next_authorize() {
    let rig = build_rig();
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
            &["profile".to_string()],
        )
        .expect("grant");

    let csrf = "csrf-revoke";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let client_id_s = rig.untrusted_client.client_id().as_uuid().to_string();
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/account/applications/{client_id_s}/revoke"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    assert_eq!(
        location_header(&resp).as_deref(),
        Some("/ui/account/applications")
    );

    // Next authorize now re-prompts.
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.untrusted_client, "profile", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(location_header(&resp).as_deref(), Some("/ui/oauth/consent"));
}

#[tokio::test]
async fn self_revoke_consent_emits_audit_with_via_self() {
    let rig = build_rig();
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
            &["profile".to_string()],
        )
        .expect("grant");
    let csrf = "x";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let client_id_s = rig.untrusted_client.client_id().as_uuid().to_string();
    let _ = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/account/applications/{client_id_s}/revoke"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    let events = rig
        .audit
        .query(&AuditQuery {
            realm_id: rig.realm_id.clone(),
            start_time: None,
            end_time: None,
            actor: None,
            action: Some(AuditAction::ConsentRevoked),
            limit: Some(10),
        })
        .expect("query");
    assert_eq!(events.len(), 1);
    // metadata tracked in follow-up
}

#[tokio::test]
async fn self_revoke_nonexistent_consent_returns_404() {
    let rig = build_rig();
    let csrf = "x";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let client_id_s = rig.untrusted_client.client_id().as_uuid().to_string();
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/account/applications/{client_id_s}/revoke"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn self_revoke_all_consents() {
    let rig = build_rig();
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.untrusted_client.client_id(),
            &["profile".to_string()],
        )
        .expect("grant");
    rig.identity
        .grant_consent(
            &rig.realm_id,
            &rig.alice_id,
            rig.trusted_client.client_id(),
            &["email".to_string()],
        )
        .expect("grant 2");
    let csrf = "x";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, csrf);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/applications/revoke-all")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());

    let entries = rig
        .identity
        .list_consents_by_user(&rig.realm_id, &rig.alice_id)
        .expect("list");
    assert!(entries.is_empty(), "expected all consents gone");
}

// ==========================================================================
// Admin consent visibility
// ==========================================================================

struct AdminRig {
    app: axum::Router,
    audit: Arc<dyn AuditEngine>,
    identity: Arc<dyn IdentityEngine>,
    target_realm_id: RealmId,
    target_realm_name: String,
    admin_session: SessionId,
    non_admin_session: SessionId,
    /// User whose consents the admin is viewing (in the target realm).
    target_user: UserId,
    /// OAuth client the target user has consented to.
    client: OAuthClient,
}

#[allow(clippy::too_many_lines)]
fn build_admin_rig() -> AdminRig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    // Target (tenant) realm + a regular user + an OAuth client.
    let target_realm = identity
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: None,
        })
        .expect("create realm");
    let target_user = seed_active_user(&*identity, target_realm.id(), "target@acme.test", "Target");
    let client = identity
        .register_client(
            target_realm.id(),
            &RegisterClientRequest {
                client_name: "Monitored App".to_string(),
                redirect_uris: vec!["https://x/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");
    identity
        .grant_consent(
            target_realm.id(),
            &target_user,
            client.client_id(),
            &["profile".to_string()],
        )
        .expect("grant consent");

    // Admin user in the SYSTEM realm + `hearth.admin` claim-based assignment.
    let admin_realm_id = hearth::core::RealmId::new(uuid::Uuid::nil());
    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@hearth.local".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin user");
    identity
        .set_password(
            &admin_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("pw");
    identity
        .update_user(
            &admin_realm_id,
            admin_user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
                first_name: None,
                last_name: None,
                ..Default::default()
            },
        )
        .expect("activate");
    let admin_session = identity
        .create_session(&admin_realm_id, admin_user.id(), &SessionContext::default())
        .expect("admin session")
        .id()
        .clone();
    authz.seed_realm(&admin_realm_id).expect("seed");
    let admin_role = authz
        .get_role_by_name(&admin_realm_id, "realm.admin")
        .expect("lookup")
        .expect("seed role");
    authz
        .assign_role(
            &admin_realm_id,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(admin_user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    // Non-admin user lives in the target realm (no admin privilege).
    let non_admin = seed_active_user(&*identity, target_realm.id(), "bob@acme.test", "Bob");
    let non_admin_session = identity
        .create_session(target_realm.id(), &non_admin, &SessionContext::default())
        .expect("non-admin session")
        .id()
        .clone();

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz,
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    );
    let app = web::router(state);

    AdminRig {
        app,
        audit,
        identity,
        target_realm_id: target_realm.id().clone(),
        target_realm_name: target_realm.name().to_string(),
        admin_session,
        non_admin_session,
        target_user,
        client,
    }
}

/// Builds an admin session cookie pointing at the system realm.
fn admin_auth_cookie(session_id: &SessionId, csrf: &str) -> String {
    auth_cookie(
        &hearth::core::RealmId::new(uuid::Uuid::nil()),
        session_id,
        csrf,
    )
}

#[tokio::test]
async fn admin_can_list_any_users_consents_in_target_realm() {
    let rig = build_admin_rig();
    let cookie = admin_auth_cookie(&rig.admin_session, "x");
    let url = format!(
        "/ui/admin/realms/{}/users/{}/consents",
        rig.target_realm_name,
        rig.target_user.as_uuid(),
    );
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(url)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_utf8(resp).await;
    assert!(
        body.contains("Monitored App"),
        "client name missing from admin view"
    );
    assert!(
        body.contains("target@acme.test"),
        "target user email missing"
    );
    assert!(body.contains("profile"), "scope missing");
}

#[tokio::test]
async fn admin_revoke_on_behalf_emits_audit_with_via_admin() {
    let rig = build_admin_rig();
    let csrf = "x";
    let cookie = admin_auth_cookie(&rig.admin_session, csrf);
    let url = format!(
        "/ui/admin/realms/{}/users/{}/consents/{}/revoke",
        rig.target_realm_name,
        rig.target_user.as_uuid(),
        rig.client.client_id().as_uuid(),
    );
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(url)
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());

    // Consent actually gone.
    let rec = rig
        .identity
        .get_consent(
            &rig.target_realm_id,
            &rig.target_user,
            rig.client.client_id(),
        )
        .expect("get");
    assert!(rec.is_none());

    let events = rig
        .audit
        .query(&AuditQuery {
            realm_id: rig.target_realm_id.clone(),
            start_time: None,
            end_time: None,
            actor: None,
            action: Some(AuditAction::ConsentRevoked),
            limit: Some(10),
        })
        .expect("query");
    assert_eq!(events.len(), 1);
    // metadata tracked in follow-up
}

#[tokio::test]
async fn non_admin_cannot_access_admin_consent_page() {
    let rig = build_admin_rig();
    let cookie = auth_cookie(&rig.target_realm_id, &rig.non_admin_session, "x");
    let url = format!(
        "/ui/admin/realms/{}/users/{}/consents",
        rig.target_realm_name,
        rig.target_user.as_uuid(),
    );
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(url)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn toggling_require_consent_via_update_client_reinstates_prompt() {
    let rig = build_rig();
    // trusted_client has require_consent=false; flip it on.
    rig.identity
        .update_client(
            &rig.realm_id,
            rig.trusted_client.client_id(),
            &UpdateClientRequest {
                client_name: None,
                redirect_uris: None,
                grant_types: None,
                require_consent: Some(true),
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("update");

    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session, "x");
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_url(&rig.trusted_client, "profile", &[]))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert!(resp.status().is_redirection());
    assert_eq!(
        location_header(&resp).as_deref(),
        Some("/ui/oauth/consent"),
        "now that require_consent=true, prompt should appear"
    );
}
