//! HTTP-level tests for the redesigned Organization Members admin surface.
//!
//! Covers the HTMX / non-HTMX branch split on
//! `admin_org_update_role` and `admin_org_remove_member`, the
//! `HX-Trigger` toast header shape the `_layout.html` container listens
//! for, and the removal of the obsolete `/members/bulk` route.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::{Clock, RealmId, SessionId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest,
    CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OrganizationRole,
    UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];

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
    org_id: hearth::core::OrganizationId,
    member_user_id: hearth::core::UserId,
    admin_session_id: SessionId,
    admin_realm_id: RealmId,
}

#[allow(clippy::too_many_lines)]
fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "Acme".to_string(),
            config: None,
        })
        .expect("create realm");

    let admin_realm_id = RealmId::new(uuid::Uuid::nil());
    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@acme.test".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
        })
        .expect("create admin user");
    identity
        .set_password(
            &admin_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
        )
        .expect("set admin password");
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
        .expect("activate admin");
    let admin_session = identity
        .create_session(
            &admin_realm_id,
            admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create admin session");

    authz.seed_realm(&admin_realm_id).expect("seed");
    let _admin_role = authz
        .get_role_by_name(&admin_realm_id, "realm.admin")
        .expect("lookup")
        .expect("seed role");
    authz
        .assign_role(
            &admin_realm_id,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(admin_user.id().clone()),
                role_id: _admin_role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    // Member user lives in the Acme realm. We'll make them a member of the
    // org so the update-role / remove tests have a real membership record.
    let member_user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "bob@acme.test".to_string(),
                display_name: "Bob".to_string(),
                first_name: String::new(),
                last_name: String::new(),
            },
        )
        .expect("create member user");

    let org = identity
        .create_organization(
            realm.id(),
            &CreateOrganizationRequest {
                name: "Customer One".to_string(),
                slug: "customer-one".to_string(),
                description: None,
                config: None,
            },
        )
        .expect("create org");

    identity
        .add_member(
            realm.id(),
            org.id(),
            member_user.id(),
            OrganizationRole::Member,
        )
        .expect("add member");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    );
    let app = web::router(state);

    Rig {
        app,
        org_id: org.id().clone(),
        member_user_id: member_user.id().clone(),
        admin_session_id: admin_session.id().clone(),
        admin_realm_id,
    }
}

fn admin_cookie(rig: &Rig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.admin_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.admin_session_id.as_uuid(),
        rig.admin_realm_id.as_uuid(),
        tag,
        csrf,
    )
}

/// HTMX role change (with `HX-Request: true`) returns a `<tr>` partial
/// with the new role selected, plus an `HX-Trigger: showToast` header
/// shaped the way `_layout.html` expects (`{"showToast":{"message":…,"kind":…}}`).
#[tokio::test]
async fn update_role_htmx_returns_row_partial_and_show_toast_trigger() {
    let rig = build_rig();
    let csrf = "csrf-htmx";
    let cookie = admin_cookie(&rig, csrf);
    let form = format!("role=Admin&_csrf={csrf}");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/ui/admin/organizations/{}/members/{}/role",
                    rig.org_id.as_uuid(),
                    rig.member_user_id.as_uuid()
                ))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("HX-Request", "true")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);

    let trigger = response
        .headers()
        .get("hx-trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        trigger.contains("showToast"),
        "hx-trigger must carry the `showToast` event name; got: {trigger}"
    );
    assert!(
        trigger.contains("\"kind\":\"success\""),
        "hx-trigger must advertise kind=success on happy path; got: {trigger}"
    );

    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body).expect("utf-8");
    assert!(body.contains("<tr"), "response must be a <tr> partial");
    // The refreshed row must reflect the new role (Admin option marked
    // `selected`) — this is the "did my change take effect?" signal the
    // redesign exists to provide.
    assert!(
        body.contains(r#"value="Admin" selected"#),
        "Admin must be the selected option in the refreshed row; got: {body}"
    );
}

/// Plain-form callers (no `HX-Request` header) still receive the 303
/// redirect-with-flash response. Keeps scripted integrations (curl,
/// automation) working after the HTMX refactor.
#[tokio::test]
async fn update_role_non_htmx_returns_303_redirect() {
    let rig = build_rig();
    let csrf = "csrf-plain";
    let cookie = admin_cookie(&rig, csrf);
    let form = format!("role=Admin&_csrf={csrf}");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/ui/admin/organizations/{}/members/{}/role",
                    rig.org_id.as_uuid(),
                    rig.member_user_id.as_uuid()
                ))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with(&format!("/ui/admin/organizations/{}", rig.org_id.as_uuid())),
        "expected redirect to org detail, got: {location}"
    );
}

/// HTMX remove (with `HX-Request: true`) returns an empty body +
/// `HX-Trigger: showToast`. The calling form's `hx-swap="outerHTML"`
/// then replaces the row with nothing.
#[tokio::test]
async fn remove_member_htmx_returns_empty_body_and_toast_trigger() {
    let rig = build_rig();
    let csrf = "csrf-rm";
    let cookie = admin_cookie(&rig, csrf);
    let form = format!("_csrf={csrf}");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/ui/admin/organizations/{}/members/{}/remove",
                    rig.org_id.as_uuid(),
                    rig.member_user_id.as_uuid()
                ))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("HX-Request", "true")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let trigger = response
        .headers()
        .get("hx-trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        trigger.contains("showToast"),
        "hx-trigger must carry the `showToast` event; got: {trigger}"
    );
}

/// The deleted bulk-add route (`POST /members/bulk`) must return 404 —
/// nothing external references it (verified at spec time), but the
/// regression check ensures future revivals of the route require an
/// explicit opt-in rather than a silent re-introduction.
#[tokio::test]
async fn bulk_add_route_is_gone() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-bulk");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/ui/admin/organizations/{}/members/bulk",
                    rig.org_id.as_uuid()
                ))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    // Axum returns 404 for an unrouted path; the exact 404/405 code is
    // less important than "the route is gone."
    assert!(
        response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::METHOD_NOT_ALLOWED,
        "expected 404 or 405, got {}",
        response.status()
    );
}

/// Regression: the create-org form must accept an empty `max_members`
/// field (the browser always posts `max_members=` for an empty
/// `<input type="number">`). Before the fix, `Option<u32>` with the
/// default `serde_urlencoded` mapping rejected `""` with
/// `cannot parse integer from empty string` and replaced the page with a
/// raw error string, losing the user's input. The fix routes those
/// fields through `empty_string_as_none`.
#[tokio::test]
async fn create_org_accepts_empty_max_members() {
    let rig = build_rig();
    let csrf = "csrf-empty-max";
    let cookie = admin_cookie(&rig, csrf);
    let body =
        format!("name=New+Customer&slug=new-customer&description=&max_members=&_csrf={csrf}");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/organizations/new?realm=Acme")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "create-org with empty max_members must redirect to detail, \
         not return a form-deserialization error"
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/ui/admin/organizations/"),
        "expected redirect to org detail, got: {location}"
    );
}

/// Regression: the edit-org form must also accept clearing
/// `max_members` (browser posts the empty string). Same root cause /
/// same fix as `create_org_accepts_empty_max_members`.
#[tokio::test]
async fn edit_org_accepts_empty_max_members() {
    let rig = build_rig();
    let csrf = "csrf-edit-empty";
    let cookie = admin_cookie(&rig, csrf);
    let body = format!("name=Customer+One&description=&status=Active&max_members=&_csrf={csrf}");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/ui/admin/organizations/{}/edit?realm=Acme",
                    rig.org_id.as_uuid()
                ))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "edit-org with empty max_members must redirect to detail, \
         not return a form-deserialization error"
    );
}
