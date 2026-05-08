//! Integration tests for the `/ui/admin/groups/*` admin UI surface.
//!
//! Smoke-level coverage: admin can render the list, create a group, view
//! its detail page, and delete it. Cycle-detection / duplicate-slug error
//! paths are exercised by `tests/admin_groups_rbac.rs` against the engine
//! directly; this file confirms the HTML handlers wire up correctly to
//! the same engine and round-trip through the router.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::{Clock, RealmId, SessionId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
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

struct TestRig {
    app: axum::Router,
    realm_id: RealmId,
    admin_session_id: SessionId,
    /// Exposed so role-assignment tests can look up the seeded
    /// `realm.admin` role by name in the application realm.
    rbac: Arc<dyn RbacEngine>,
}

#[allow(clippy::too_many_lines)]
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
    )) as Arc<dyn hearth::audit::AuditEngine>;
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

    let admin_realm_id = RealmId::new(uuid::Uuid::nil());
    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@acme.test".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
        })
        .expect("create admin user");
    let pw = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(&admin_realm_id, admin_user.id(), &pw)
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

    authz
        .seed_realm(&admin_realm_id)
        .expect("seed system realm");
    // Seed the application realm so role-assignment tests have at least
    // one role (e.g. `realm.admin`) available to assign.
    authz
        .seed_realm(realm.id())
        .expect("seed application realm");
    let admin_role = authz
        .get_role_by_name(&admin_realm_id, "realm.admin")
        .expect("lookup role")
        .expect("seed role present");
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

    TestRig {
        app,
        realm_id: realm.id().clone(),
        admin_session_id: admin_session.id().clone(),
        rbac: Arc::clone(&authz),
    }
}

fn admin_cookie(rig: &TestRig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let admin_realm = RealmId::new(uuid::Uuid::nil());
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(admin_realm.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.admin_session_id.as_uuid(),
        admin_realm.as_uuid(),
        tag,
        csrf,
    )
}

#[tokio::test]
async fn groups_list_renders_empty_state_for_admin() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-list");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/groups")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let html = std::str::from_utf8(&body).expect("utf8");
    // Empty-state copy is the canonical signal that the page rendered the
    // intended template (rather than e.g. a 200 from a stub).
    assert!(
        html.contains("No groups yet"),
        "missing empty state in body"
    );
    assert!(
        html.contains("Create your first group"),
        "missing CTA in empty state",
    );
}

#[tokio::test]
async fn admin_can_create_view_and_delete_a_group() {
    let rig = build_rig();
    let csrf = "csrf-roundtrip";
    let cookie = admin_cookie(&rig, csrf);

    // Create.
    let body = format!("name=Engineering&slug=engineering&description=&_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/groups/new")
                .header(header::COOKIE, cookie.clone())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "create should redirect to detail page",
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location header")
        .to_string();
    assert!(
        location.starts_with("/ui/admin/realms/acme/groups/"),
        "redirect should point at group detail, got {location}",
    );

    // Confirm the detail page renders.
    let detail_response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&location)
                .header(header::COOKIE, cookie.clone())
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(detail_response.status(), StatusCode::OK);
    let detail_body = to_bytes(detail_response.into_body(), 1 << 20)
        .await
        .expect("body");
    let detail_html = std::str::from_utf8(&detail_body).expect("utf8");
    assert!(
        detail_html.contains("Engineering"),
        "detail page should render group name",
    );
    assert!(
        detail_html.contains("engineering"),
        "detail page should render group slug",
    );

    // Confirm the new group shows up in the list (no longer empty state).
    let list_response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/groups")
                .header(header::COOKIE, cookie.clone())
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_html = String::from_utf8(
        to_bytes(list_response.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8");
    assert!(list_html.contains("Engineering"));
    assert!(!list_html.contains("No groups yet"));

    // Delete. `location` is `/ui/admin/realms/acme/groups/<uuid>`; append
    // `/delete` to construct the deletion endpoint.
    let delete_url = format!("{location}/delete");
    let delete_body = format!("_csrf={csrf}");
    let delete_response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&delete_url)
                .header(header::COOKIE, cookie.clone())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(delete_body))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        delete_response.status(),
        StatusCode::SEE_OTHER,
        "delete should redirect to list",
    );

    // After delete, list should be empty again.
    let post_delete_list = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/groups")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(post_delete_list.status(), StatusCode::OK);
    let post_html = String::from_utf8(
        to_bytes(post_delete_list.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8");
    assert!(
        post_html.contains("No groups yet"),
        "list should be empty after delete",
    );
}

#[tokio::test]
async fn create_with_duplicate_slug_re_renders_form_with_error() {
    let rig = build_rig();
    let csrf = "csrf-dup";
    let cookie = admin_cookie(&rig, csrf);

    let body = format!("name=Engineering&slug=engineering&description=&_csrf={csrf}");
    // First create — should succeed.
    let r1 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/groups/new")
                .header(header::COOKIE, cookie.clone())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.clone()))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(r1.status(), StatusCode::SEE_OTHER);

    // Second create with same slug — should re-render the form (200) with
    // the duplicate-slug error banner. NOT a 5xx, NOT a redirect.
    let r2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/groups/new")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(r2.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(r2.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8");
    assert!(
        html.contains("group with that slug already exists"),
        "expected duplicate-slug error banner; got: {}",
        &html[..html.len().min(500)],
    );
}

#[allow(dead_code)]
fn _ensure_realm_id_used_to_silence_dead_code(rig: &TestRig) {
    // The realm_id field is captured for completeness; this no-op keeps
    // clippy happy if a future test stops referencing it directly.
    let _ = &rig.realm_id;
}

#[tokio::test]
async fn admin_can_assign_realm_role_to_group() {
    let rig = build_rig();
    let csrf = "csrf-roles";
    let cookie = admin_cookie(&rig, csrf);

    // Create a group to assign the role to.
    let create_body = format!("name=Engineering&slug=engineering&description=&_csrf={csrf}");
    let create_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/groups/new")
                .header(header::COOKIE, cookie.clone())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(create_body))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(create_resp.status(), StatusCode::SEE_OTHER);
    let group_path = create_resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location")
        .to_string();

    // Look up the seeded `realm.admin` role in the application realm.
    // The rig calls `authz.seed_realm(realm.id())` for exactly this — every
    // realm gets a small set of default roles when seeded, including
    // `realm.admin`.
    let role = rig
        .rbac
        .get_role_by_name(&rig.realm_id, "realm.admin")
        .expect("get_role_by_name")
        .expect("seeded realm.admin role present");
    let role_uuid = role.id.as_uuid().to_string();

    // Assign with realm scope.
    let assign_body = format!("role_id={role_uuid}&scope=realm&_csrf={csrf}");
    let assign_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{group_path}/roles/assign"))
                .header(header::COOKIE, cookie.clone())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(assign_body))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        assign_resp.status(),
        StatusCode::SEE_OTHER,
        "assign should redirect with flash",
    );

    // GET the Roles tab and confirm the role appears in the assignments
    // table. Look for a "Realm" scope label and the role name to be sure
    // we're seeing the assignment row, not just the assign-form dropdown
    // (which also lists every available role).
    let detail_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("{group_path}?tab=roles"))
                .header(header::COOKIE, cookie.clone())
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(detail_resp.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(detail_resp.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8");
    assert!(
        html.contains("realm.admin"),
        "expected role name in rendered Roles tab",
    );
    // The assignments table renders "Realm" in the scope column for
    // realm-scoped assignments. Empty-state message would be present
    // INSTEAD if no assignment landed, so its absence confirms the row
    // landed in the table.
    assert!(
        !html.contains("No roles assigned to this group yet"),
        "empty-state should be gone after a successful assign",
    );
}
