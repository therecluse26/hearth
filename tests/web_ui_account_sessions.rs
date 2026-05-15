//! Integration tests for `/ui/account/sessions` — self-service session
//! management. Drives the axum router via `tower::ServiceExt::oneshot`
//! and covers listing, individual revocation (including the critical
//! ownership check), "revoke all other devices", current-session logout,
//! CSRF enforcement, and the audit trail.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::audit::{AuditAction, AuditEngine, AuditQuery};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, SessionContext, UpdateUserRequest,
    UserStatus,
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

struct TestRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    audit: Arc<dyn AuditEngine>,
    realm_id: RealmId,
    alice_id: UserId,
    alice_session_current: SessionId,
    alice_session_other: SessionId,
    bob_id: UserId,
    bob_session: SessionId,
}

fn build_rig() -> TestRig {
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

    let ctx_current = SessionContext {
        ip_address: Some("198.51.100.10".to_string()),
        user_agent_raw: Some("Mozilla/5.0 (Macintosh; Intel Mac OS X)".to_string()),
        device_label: Some("This device".to_string()),
        satisfies_mfa_via_passkey: false,
    };
    let ctx_other = SessionContext {
        ip_address: Some("198.51.100.20".to_string()),
        user_agent_raw: Some("Mozilla/5.0 (iPhone)".to_string()),
        device_label: Some("Other phone".to_string()),
        satisfies_mfa_via_passkey: false,
    };
    let alice_session_current = identity
        .create_session(realm.id(), &alice, &ctx_current)
        .expect("alice current session")
        .id()
        .clone();
    let alice_session_other = identity
        .create_session(realm.id(), &alice, &ctx_other)
        .expect("alice other session")
        .id()
        .clone();
    let bob_session = identity
        .create_session(realm.id(), &bob, &SessionContext::default())
        .expect("bob session")
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

    TestRig {
        app,
        identity,
        audit,
        realm_id: realm.id().clone(),
        alice_id: alice,
        alice_session_current,
        alice_session_other,
        bob_id: bob,
        bob_session,
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
        .expect("activate user");
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

async fn body_utf8(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

#[tokio::test]
async fn sessions_index_lists_only_own_sessions() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session_current, "csrf-x");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account/sessions")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_utf8(response).await;
    // Alice sees both her session IDs rendered (look for substring of each UUID).
    assert!(
        body.contains(&rig.alice_session_current.as_uuid().to_string()),
        "current session missing from listing"
    );
    assert!(
        body.contains(&rig.alice_session_other.as_uuid().to_string()),
        "other own session missing from listing"
    );
    // Bob's session UUID MUST NOT appear.
    assert!(
        !body.contains(&rig.bob_session.as_uuid().to_string()),
        "leaked another user's session into Alice's page"
    );
    assert!(body.contains("This device"), "expected device label");
}

#[tokio::test]
async fn sessions_index_marks_current_session() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session_current, "csrf-x");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account/sessions")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_utf8(response).await;
    // The page should carry an explicit "this device" marker.
    // We deliberately search for the exact badge text so we know the
    // template distinguishes the current row, not just renders both.
    assert!(
        body.contains("data-current-session"),
        "expected data-current-session attribute marking the current row, got: {body}",
    );
}

#[tokio::test]
async fn revoke_own_session_succeeds_and_writes_audit() {
    let rig = build_rig();
    let csrf = "csrf-revoke-own";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session_current, csrf);

    let body = format!("_csrf={csrf}");
    let target = rig.alice_session_other.as_uuid();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/account/sessions/{target}/revoke"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    // PRG redirect back to the index page on success.
    assert!(
        response.status().is_redirection(),
        "expected redirect, got {}",
        response.status()
    );

    // Revoked session is gone; current session is intact.
    let other = rig
        .identity
        .get_session(&rig.realm_id, &rig.alice_session_other)
        .expect("get other");
    assert!(other.is_none(), "other session should be revoked/removed");
    let current = rig
        .identity
        .get_session(&rig.realm_id, &rig.alice_session_current)
        .expect("get current");
    assert!(current.is_some(), "current session must still be valid");

    // Audit event written with actor = alice's uuid and via = self.
    let events = rig
        .audit
        .query(&AuditQuery {
            action: Some(AuditAction::SessionRevoked),
            ..AuditQuery::for_realm(rig.realm_id.clone())
        })
        .expect("query audit");
    let hit = events
        .iter()
        .find(|e| e.resource_id == rig.alice_session_other.as_uuid().to_string())
        .expect("self-revoke audit event present");
    assert_eq!(hit.actor, rig.alice_id.as_uuid().to_string());
    // metadata (via) tracked in metadata-threading follow-up
}

#[tokio::test]
async fn revoke_other_users_session_is_rejected() {
    let rig = build_rig();
    let csrf = "csrf-xuser";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session_current, csrf);

    let target = rig.bob_session.as_uuid();
    let body = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/account/sessions/{target}/revoke"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "expected 404 ownership rejection"
    );

    // Bob's session must still exist.
    let bob_sess = rig
        .identity
        .get_session(&rig.realm_id, &rig.bob_session)
        .expect("get bob");
    assert!(
        bob_sess.is_some(),
        "cross-user revoke must not destroy victim session"
    );

    // No audit event written for this attempted revocation.
    let events = rig
        .audit
        .query(&AuditQuery {
            action: Some(AuditAction::SessionRevoked),
            ..AuditQuery::for_realm(rig.realm_id.clone())
        })
        .expect("query audit");
    assert!(
        events
            .iter()
            .all(|e| e.resource_id != rig.bob_session.as_uuid().to_string()),
        "must not audit a revocation that was rejected",
    );
    let _ = rig.bob_id;
}

#[tokio::test]
async fn revoke_current_session_clears_cookie_and_redirects_to_login() {
    let rig = build_rig();
    let csrf = "csrf-current";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session_current, csrf);
    let target = rig.alice_session_current.as_uuid();

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/account/sessions/{target}/revoke"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert!(response.status().is_redirection());
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        location.ends_with("/ui/login") || location == "/ui/login",
        "expected redirect to /ui/login, got {location}",
    );

    // Cookie-clearing Set-Cookie headers must be present for both cookies.
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    assert!(
        set_cookies
            .iter()
            .any(|h| h.starts_with("hearth_ui_session=") && h.contains("Max-Age=0")),
        "expected session cookie clearing header, got {set_cookies:?}",
    );

    // Session really is revoked on the server.
    let sess = rig
        .identity
        .get_session(&rig.realm_id, &rig.alice_session_current)
        .expect("get current");
    assert!(sess.is_none(), "current session must be revoked");
}

#[tokio::test]
async fn revoke_others_revokes_all_but_current() {
    let rig = build_rig();
    // Seed a third session for Alice.
    let third = rig
        .identity
        .create_session(&rig.realm_id, &rig.alice_id, &SessionContext::default())
        .expect("third session")
        .id()
        .clone();

    let csrf = "csrf-others";
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session_current, csrf);
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/account/sessions/revoke-others")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert!(response.status().is_redirection());

    // Current lives; the other two are revoked.
    assert!(rig
        .identity
        .get_session(&rig.realm_id, &rig.alice_session_current)
        .expect("get current")
        .is_some());
    assert!(rig
        .identity
        .get_session(&rig.realm_id, &rig.alice_session_other)
        .expect("get other")
        .is_none());
    assert!(rig
        .identity
        .get_session(&rig.realm_id, &third)
        .expect("get third")
        .is_none());

    // Bob's session is untouched.
    assert!(rig
        .identity
        .get_session(&rig.realm_id, &rig.bob_session)
        .expect("get bob")
        .is_some());
}

#[tokio::test]
async fn csrf_missing_rejects_revoke() {
    let rig = build_rig();
    let cookie = auth_cookie(&rig.realm_id, &rig.alice_session_current, "csrf-actual");
    let target = rig.alice_session_other.as_uuid();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/account/sessions/{target}/revoke"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("_csrf=wrong"))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Session untouched.
    let still = rig
        .identity
        .get_session(&rig.realm_id, &rig.alice_session_other)
        .expect("get other");
    assert!(still.is_some(), "csrf failure must not revoke the session");
}
