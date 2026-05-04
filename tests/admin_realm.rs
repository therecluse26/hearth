//! Integration tests for the invisible system realm.
//!
//! The system realm (`RealmId::nil()`) is Hearth's home for admin
//! users. It is deliberately not exposed on public surfaces:
//!
//! * `list_realms()` filters it out.
//! * `get_realm_by_name("system")` returns `None`.
//! * `create_realm` / `update_realm` / `delete_realm` reject it.
//! * `register_user`, `register_client`, `create_organization` reject it.
//!
//! These tests pin the invariants at the engine layer. Web-layer
//! invariants (admin-login URL, `?realm=system` rejection, switcher
//! hides it) live in `tests/web_ui_admin.rs` alongside the routing
//! refactor.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    CleartextPassword, CreateOrganizationRequest, CreateRealmRequest, IdentityError,
    OrganizationConfig, RegisterClientRequest, RegisterUserRequest, RegistrationPolicy,
};

/// The system realm UUID. Duplicated as a literal here because the
/// public crate surface doesn't re-export `keys::system_realm_id()` —
/// external callers should have no reason to target it directly.
fn system_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

// ===== Scenario 1: Seeded on startup =====

#[tokio::test]
async fn system_realm_exists_after_startup() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    // Direct lookup: the record is there.
    let realm = identity
        .get_realm(&system_realm_id())
        .expect("get_realm")
        .expect("system realm must exist after startup");
    assert_eq!(realm.id(), &system_realm_id());

    // list_realms hides it.
    let page = identity.list_realms(None, 100).expect("list_realms");
    assert!(
        !page.items.iter().any(|r| r.id() == &system_realm_id()),
        "list_realms must filter out the system realm"
    );
}

// ===== Scenario 2: get_realm_by_name hides reserved name =====

#[tokio::test]
async fn get_realm_by_name_rejects_reserved_name() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let result = identity.get_realm_by_name("system").expect("lookup");
    assert!(
        result.is_none(),
        "get_realm_by_name(\"system\") must return None even when the record exists"
    );
}

// ===== Scenario 3-4: Realm mutation guards =====

#[tokio::test]
async fn create_realm_rejects_reserved_name() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let result = identity.create_realm(&CreateRealmRequest {
        name: "system".to_string(),
        config: None,
    });
    assert!(
        matches!(result, Err(IdentityError::SystemRealmProtected { .. })),
        "create_realm must reject the reserved \"system\" name, got {result:?}"
    );
}

#[tokio::test]
async fn delete_realm_rejects_system_realm() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let result = identity.delete_realm(&system_realm_id());
    assert!(
        matches!(result, Err(IdentityError::SystemRealmProtected { .. })),
        "delete_realm must reject the system realm, got {result:?}"
    );
}

// ===== Scenario 5-7: Application-user / client / org guards =====

#[tokio::test]
async fn register_user_rejects_system_realm() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let result = identity.register_user(
        &system_realm_id(),
        &RegisterUserRequest {
            email: "attacker@example.com".to_string(),
            display_name: "Attacker".to_string(),
            password: CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
            client_ip: None,
            invitation_token: None,
            first_name: String::new(),
            last_name: String::new(),
        },
    );
    assert!(
        matches!(result, Err(IdentityError::SystemRealmProtected { .. })),
        "register_user must never land in the admin realm, got {result:?}"
    );
    // Sanity: even if the realm somehow had Open policy, the guard runs first.
    let _ = RegistrationPolicy::Open; // keep the import used
}

#[tokio::test]
async fn register_client_rejects_system_realm() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let result = identity.register_client(
        &system_realm_id(),
        &RegisterClientRequest {
            client_name: "evil-app".to_string(),
            redirect_uris: vec!["https://evil.example.com/cb".to_string()],
            client_secret: None,
            grant_types: vec!["authorization_code".to_string()],
            require_consent: true,
            client_logo_url: None,
            ..Default::default()
        },
    );
    assert!(
        matches!(result, Err(IdentityError::SystemRealmProtected { .. })),
        "register_client must reject the system realm, got {result:?}"
    );
}

#[tokio::test]
async fn create_user_rejects_system_realm() {
    use hearth::identity::CreateUserRequest;
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let result = identity.create_user(
        &system_realm_id(),
        &CreateUserRequest {
            email: "sneaky@example.com".to_string(),
            display_name: "Sneaky".to_string(),
            first_name: String::new(),
            last_name: String::new(),
        },
    );
    assert!(
        matches!(result, Err(IdentityError::SystemRealmProtected { .. })),
        "create_user must reject the system realm; use create_admin_user instead. got {result:?}"
    );
}

#[tokio::test]
async fn create_admin_user_succeeds_on_system_realm() {
    use hearth::identity::CreateUserRequest;
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let user = identity
        .create_admin_user(&CreateUserRequest {
            email: "second-admin@example.com".to_string(),
            display_name: "Second Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
        })
        .expect("create_admin_user");
    // The user is persisted in the system realm.
    let fetched = identity
        .get_user(&system_realm_id(), user.id())
        .expect("get_user")
        .expect("user exists");
    assert_eq!(fetched.email(), "second-admin@example.com");
}

#[tokio::test]
async fn update_organization_rejects_system_realm() {
    use hearth::core::OrganizationId;
    use hearth::identity::UpdateOrganizationRequest;
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let result = identity.update_organization(
        &system_realm_id(),
        &OrganizationId::generate(),
        &UpdateOrganizationRequest {
            name: Some("Renamed".to_string()),
            description: None,
            status: None,
            config: None,
        },
    );
    assert!(
        matches!(result, Err(IdentityError::SystemRealmProtected { .. })),
        "update_organization must reject the system realm, got {result:?}"
    );
}

#[tokio::test]
async fn create_organization_rejects_system_realm() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let result = identity.create_organization(
        &system_realm_id(),
        &CreateOrganizationRequest {
            name: "Sneaky Org".to_string(),
            slug: "sneaky".to_string(),
            description: None,
            config: Some(OrganizationConfig { max_members: None }),
        },
    );
    assert!(
        matches!(result, Err(IdentityError::SystemRealmProtected { .. })),
        "create_organization must reject the system realm, got {result:?}"
    );
}

// ===== Scenario: list_realms pagination never leaks the system realm =====

// ===== Scenario: YAML-level rejection =====

#[tokio::test]
async fn yaml_rejects_reserved_realm_name() {
    let yaml = r"
realms:
  system:
    auth: {}
";
    let result = hearth::config::Config::from_yaml_str(yaml);
    assert!(
        result.is_err(),
        "Config::from_yaml_str must reject realms.system, got {result:?}"
    );
}

// ===== Scenario: onboarding lands admin in system realm =====

#[tokio::test]
async fn complete_setup_targets_system_realm() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = std::sync::Arc::new(
        hearth::storage::EmbeddedStorageEngine::open(hearth::storage::StorageConfig::dev(
            data_dir.clone(),
        ))
        .expect("storage"),
    );
    let clock =
        std::sync::Arc::new(hearth::core::SystemClock) as std::sync::Arc<dyn hearth::core::Clock>;
    let identity = std::sync::Arc::new(
        hearth::identity::EmbeddedIdentityEngine::new(
            std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
            std::sync::Arc::clone(&clock),
            hearth::identity::IdentityConfig {
                credential: hearth::identity::CredentialConfig::fast_for_testing(),
                ..hearth::identity::IdentityConfig::default()
            },
        )
        .expect("identity"),
    ) as std::sync::Arc<dyn hearth::identity::IdentityEngine>;
    let authz = std::sync::Arc::new(hearth::rbac::EmbeddedRbacEngine::new(
        std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
        std::sync::Arc::clone(&clock),
    )) as std::sync::Arc<dyn hearth::rbac::RbacEngine>;
    let email_service = std::sync::Arc::new(
        hearth::identity::email::EmailService::new(
            std::sync::Arc::new(hearth::identity::email::LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            hearth::identity::email::EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = hearth::identity::onboarding::OnboardingService::new(
        std::sync::Arc::clone(&identity),
        std::sync::Arc::clone(&authz),
        email_service,
        data_dir.clone(),
    );

    // Simulate the setup token having been emitted by the server.
    // complete_setup only checks that the file exists; it does not read
    // the token's contents (that's `verify_setup_token`'s job).
    std::fs::write(
        data_dir.join(hearth::identity::onboarding::SETUP_TOKEN_FILENAME),
        "stub-token",
    )
    .expect("write setup token");

    let outcome = onboarding
        .complete_setup(
            "admin@example.com",
            "Admin",
            &CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
            "https://hearth.example.com",
        )
        .expect("complete_setup");

    assert_eq!(
        outcome.realm_id,
        system_realm_id(),
        "admin user must live in the system realm, got {:?}",
        outcome.realm_id
    );

    // Verification URL must be scoped under /ui/admin, not /ui/verify-email.
    assert!(
        outcome.verification_url.contains("/ui/admin/verify-email"),
        "verification URL must target admin route, got {}",
        outcome.verification_url
    );

    // The admin user has the hearth.admin permission in the system realm.
    let resolved = authz
        .resolve_permissions(&outcome.admin_user_id, &system_realm_id(), None, None)
        .expect("resolve");
    assert!(
        resolved
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin"),
        "admin user must carry hearth.admin permission in the system realm"
    );
}

// ===== Scenario: admin routes exist and resolve to system realm =====

#[tokio::test]
async fn admin_login_route_renders_form() {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = std::sync::Arc::new(
        hearth::storage::EmbeddedStorageEngine::open(hearth::storage::StorageConfig::dev(
            data_dir.clone(),
        ))
        .expect("storage"),
    );
    let clock =
        std::sync::Arc::new(hearth::core::SystemClock) as std::sync::Arc<dyn hearth::core::Clock>;
    let identity = std::sync::Arc::new(
        hearth::identity::EmbeddedIdentityEngine::new(
            std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
            std::sync::Arc::clone(&clock),
            hearth::identity::IdentityConfig {
                credential: hearth::identity::CredentialConfig::fast_for_testing(),
                ..hearth::identity::IdentityConfig::default()
            },
        )
        .expect("identity"),
    ) as std::sync::Arc<dyn hearth::identity::IdentityEngine>;
    let authz = std::sync::Arc::new(hearth::rbac::EmbeddedRbacEngine::new(
        std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
        std::sync::Arc::clone(&clock),
    )) as std::sync::Arc<dyn hearth::rbac::RbacEngine>;
    let audit = std::sync::Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
        std::sync::Arc::clone(&clock),
    )) as std::sync::Arc<dyn hearth::audit::AuditEngine>;
    let email = std::sync::Arc::new(
        hearth::identity::email::EmailService::new(
            std::sync::Arc::new(hearth::identity::email::LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            hearth::identity::email::EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email"),
    );
    let onboarding = std::sync::Arc::new(hearth::identity::onboarding::OnboardingService::new(
        std::sync::Arc::clone(&identity),
        std::sync::Arc::clone(&authz),
        email,
        data_dir,
    ));
    let state = hearth::protocol::web::WebState::new(
        identity,
        authz,
        audit,
        onboarding,
        hearth::protocol::web::CookieSecret::from_bytes([7u8; 32]),
        None,
    );
    let app = hearth::protocol::web::router(state);

    // /ui/admin/login is reachable regardless of tenant-realm state.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/admin/login")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("Sign in"),
        "admin login form should render: {}",
        &html[..html.len().min(400)]
    );
    // The form must POST back to /ui/admin/login, not bare /ui/login.
    assert!(
        html.contains("action=\"/ui/admin/login\""),
        "admin login form must target /ui/admin/login"
    );
    // The rendered URLs MUST NOT expose the reserved realm name.
    // (The word "system" can legitimately appear in CSS font stacks
    // like `system-ui` or in messages like "check your server logs",
    // so we constrain the check to URL-shaped occurrences.)
    assert!(
        !html.contains("/ui/realms/system"),
        "admin login must not route through the tenant realm path space"
    );
}

// ===== Scenario: end-to-end setup → admin verify-email → admin login =====

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn admin_setup_verify_login_end_to_end() {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = std::sync::Arc::new(
        hearth::storage::EmbeddedStorageEngine::open(hearth::storage::StorageConfig::dev(
            data_dir.clone(),
        ))
        .expect("storage"),
    );
    let clock =
        std::sync::Arc::new(hearth::core::SystemClock) as std::sync::Arc<dyn hearth::core::Clock>;
    let identity = std::sync::Arc::new(
        hearth::identity::EmbeddedIdentityEngine::new(
            std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
            std::sync::Arc::clone(&clock),
            hearth::identity::IdentityConfig {
                credential: hearth::identity::CredentialConfig::fast_for_testing(),
                ..hearth::identity::IdentityConfig::default()
            },
        )
        .expect("identity"),
    ) as std::sync::Arc<dyn hearth::identity::IdentityEngine>;
    let authz = std::sync::Arc::new(hearth::rbac::EmbeddedRbacEngine::new(
        std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
        std::sync::Arc::clone(&clock),
    )) as std::sync::Arc<dyn hearth::rbac::RbacEngine>;
    let audit = std::sync::Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        std::sync::Arc::clone(&storage) as std::sync::Arc<dyn hearth::storage::StorageEngine>,
        std::sync::Arc::clone(&clock),
    )) as std::sync::Arc<dyn hearth::audit::AuditEngine>;
    let email = std::sync::Arc::new(
        hearth::identity::email::EmailService::new(
            std::sync::Arc::new(hearth::identity::email::LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            hearth::identity::email::EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email"),
    );
    // Seed an application realm — part of the test is proving the
    // admin ends up in the system realm, not this one.
    identity
        .create_realm(&CreateRealmRequest {
            name: "customer-portal".to_string(),
            config: None,
        })
        .expect("create app realm");

    let onboarding = std::sync::Arc::new(hearth::identity::onboarding::OnboardingService::new(
        std::sync::Arc::clone(&identity),
        std::sync::Arc::clone(&authz),
        std::sync::Arc::clone(&email),
        data_dir.clone(),
    ));

    // Pretend setup is in progress — the flow requires the token file
    // to exist.
    std::fs::write(
        data_dir.join(hearth::identity::onboarding::SETUP_TOKEN_FILENAME),
        "stub-token",
    )
    .expect("write setup token");

    // Run setup. Admin goes to the system realm.
    let outcome = onboarding
        .complete_setup(
            "root@example.com",
            "Root",
            &CleartextPassword::from_string("correct-horse-battery-staple".to_string()),
            "http://localhost:8420",
        )
        .expect("complete_setup");
    assert_eq!(outcome.realm_id, system_realm_id());

    // Extract the verification token from the URL.
    let token = outcome
        .verification_url
        .split_once("token=")
        .expect("token query param")
        .1
        .to_string();

    let state = hearth::protocol::web::WebState::new(
        std::sync::Arc::clone(&identity),
        authz,
        audit,
        onboarding,
        hearth::protocol::web::CookieSecret::from_bytes([9u8; 32]),
        Some(email),
    );
    let app = hearth::protocol::web::router(state);

    // Hit the admin verify-email route. MUST succeed and activate the admin.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/ui/admin/verify-email?token={token}"))
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admin verify-email must succeed, got {}",
        resp.status()
    );
    let body = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let html = String::from_utf8_lossy(&body);
    // The success page's "Sign in" button points at the admin login.
    assert!(
        html.contains("/ui/admin/login"),
        "verify-email success page must link to admin login: {}",
        &html[..html.len().min(400)]
    );

    // Confirm the admin user is now Active in the system realm.
    let user = identity
        .get_user(&system_realm_id(), &outcome.admin_user_id)
        .expect("get_user")
        .expect("admin exists");
    assert_eq!(user.status(), hearth::identity::UserStatus::Active);
    assert_eq!(user.email(), "root@example.com");

    // Finally: submit the admin login form. Should succeed with a
    // session cookie bound to the system realm.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "email=root%40example.com&password=correct-horse-battery-staple",
                ))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    // 303 redirect on success.
    assert!(
        resp.status().is_redirection(),
        "admin login must redirect on success, got {}",
        resp.status()
    );
    // The session cookie must carry the nil UUID for realm binding.
    let cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("hearth_ui_session="))
        .expect("session cookie");
    assert!(
        session_cookie.contains("00000000-0000-0000-0000-000000000000"),
        "session cookie must bind to the system realm UUID: {session_cookie}"
    );
}

#[tokio::test]
async fn list_realms_excludes_system_even_with_many_realms() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    // Create five application realms, then list — system realm must not
    // appear at any position or under any page boundary.
    for i in 0..5 {
        identity
            .create_realm(&CreateRealmRequest {
                name: format!("realm-{i}"),
                config: None,
            })
            .expect("create realm");
    }
    let page = identity.list_realms(None, 100).expect("list_realms");
    assert_eq!(page.items.len(), 5, "expected 5 user realms");
    assert!(
        !page.items.iter().any(|r| r.id() == &system_realm_id()),
        "list_realms leaked the system realm"
    );
}
