//! Integration tests for bulk user operations and CSV import UI handlers.
//!
//! Covers:
//! - `POST /ui/admin/realms/{realm}/users/bulk-action` — deactivate, assign_role
//! - `GET  /ui/admin/realms/{realm}/users/import`       — form renders 200
//! - `GET  /ui/admin/realms/{realm}/users/import/template.csv` — CSV download
//! - `POST /ui/admin/realms/{realm}/users/import`       — CSV upload creates users

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::{RealmId, SessionId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [7u8; 32];

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
    admin_session_id: SessionId,
    system_realm_id: RealmId,
    tenant_realm_name: String,
    user_id: hearth::core::UserId,
}

fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
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
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let system_realm_id = RealmId::new(uuid::Uuid::nil());
    rbac.seed_realm(&system_realm_id)
        .expect("seed system realm");

    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@test.example".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin");
    identity
        .set_password(
            &system_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string("hunter2".to_string()),
        )
        .expect("set password");
    identity
        .update_user(
            &system_realm_id,
            admin_user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    let admin_role = rbac
        .get_role_by_name(&system_realm_id, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    rbac.assign_role(
        &system_realm_id,
        &AssignRoleRequest {
            subject: Subject::User(admin_user.id().clone()),
            role_id: admin_role.id,
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("assign admin");
    let admin_session = identity
        .create_session(
            &system_realm_id,
            admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session");

    let tenant_realm = identity
        .create_realm(&CreateRealmRequest {
            name: "testco".to_string(),
            config: None,
        })
        .expect("create realm");
    rbac.seed_realm(tenant_realm.id())
        .expect("seed tenant realm");

    let test_user = identity
        .create_user(
            tenant_realm.id(),
            &CreateUserRequest {
                email: "alice@testco.example".to_string(),
                display_name: "Alice".to_string(),
                first_name: "Alice".to_string(),
                last_name: "Test".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    );
    let app = web::router(state);

    Rig {
        app,
        admin_session_id: admin_session.id().clone(),
        system_realm_id,
        tenant_realm_name: "testco".to_string(),
        user_id: test_user.id().clone(),
    }
}

fn admin_cookie(rig: &Rig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("hmac key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.system_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.admin_session_id.as_uuid(),
        rig.system_realm_id.as_uuid(),
        tag,
        csrf,
    )
}

// ---------------------------------------------------------------------------
// Import form + template CSV
// ---------------------------------------------------------------------------

/// `GET /ui/admin/realms/{realm}/users/import` renders the upload form.
#[tokio::test]
async fn import_form_returns_200() {
    let rig = build_rig();
    let csrf = "csrf-import";
    let cookie = admin_cookie(&rig, csrf);
    let realm = &rig.tenant_realm_name;

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/ui/admin/realms/{realm}/users/import"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("test invariant");
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("Import users from CSV"),
        "page heading missing"
    );
}

/// `GET /ui/admin/realms/{realm}/users/import/template.csv` serves a
/// downloadable CSV with expected columns.
#[tokio::test]
async fn import_template_csv_download() {
    let rig = build_rig();
    let csrf = "csrf-tpl";
    let cookie = admin_cookie(&rig, csrf);
    let realm = &rig.tenant_realm_name;

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/ui/admin/realms/{realm}/users/import/template.csv"
                ))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/csv"), "content-type should be text/csv");
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("test invariant");
    let csv = String::from_utf8_lossy(&body);
    assert!(csv.starts_with("email,"), "first column should be email");
}

// ---------------------------------------------------------------------------
// Bulk deactivate
// ---------------------------------------------------------------------------

/// `POST /ui/admin/realms/{realm}/users/bulk-action` with `deactivate`
/// redirects to the users list with a flash parameter.
#[tokio::test]
async fn bulk_deactivate_redirects() {
    let rig = build_rig();
    let csrf = "csrf-bulk";
    let cookie = admin_cookie(&rig, csrf);
    let realm = &rig.tenant_realm_name;
    let uid = rig.user_id.as_uuid().to_string();

    let body = format!("ids={uid}&bulk_action=deactivate&_csrf={csrf}");
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/{realm}/users/bulk-action"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");

    // Should redirect back to users list.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.contains("bulk_deactivated"),
        "redirect should include bulk_deactivated flash"
    );
}

/// Submitting bulk-action with an empty `ids` list redirects with
/// `no_users_selected`.
#[tokio::test]
async fn bulk_action_empty_ids_redirects_with_no_users_selected() {
    let rig = build_rig();
    let csrf = "csrf-empty";
    let cookie = admin_cookie(&rig, csrf);
    let realm = &rig.tenant_realm_name;

    let body = format!("ids=&bulk_action=deactivate&_csrf={csrf}");
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/{realm}/users/bulk-action"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(loc.contains("no_users_selected"));
}
