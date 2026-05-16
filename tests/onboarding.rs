//! Integration tests for production onboarding (Phase 1.5 / Step 32).
//!
//! Covers `TEST_SCENARIOS.md` § Onboarding (Setup + Email Verification):
//! - First-run detection toggles when the first realm is created.
//! - Setup-token lifecycle: generated once, consumed on success, removed
//!   automatically when the deployment becomes configured.
//! - Full setup flow: admin (`PendingVerification`) + realm.admin RBAC
//!   assignment + verification token + verification email (realm comes
//!   from YAML reconciliation, pre-created in tests via `seed_realm`).
//! - Session creation is gated on `UserStatus::Active`; a
//!   `PendingVerification` user cannot create sessions.
//! - Verification-token reuse, expiry, and enumeration-resistance.
//!
//! The tests build their own engine stack rather than going through
//! `TestHarness` because `OnboardingService` requires `Arc<dyn Trait>`
//! handles and the harness exposes trait references.

use std::sync::{Arc, Mutex};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::{EmailBranding, EmailError, EmailMessage, EmailSender, EmailService};
use hearth::identity::onboarding::{
    consume_setup_token, ensure_setup_token, is_first_run, OnboardingError, OnboardingService,
    SETUP_TOKEN_FILENAME,
};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, Realm, UserStatus,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Test-only email sender that records every sent [`EmailMessage`].
#[derive(Default)]
struct RecordingEmailSender {
    messages: Mutex<Vec<EmailMessage>>,
}

impl RecordingEmailSender {
    fn last(&self) -> Option<EmailMessage> {
        self.messages.lock().expect("lock").last().cloned()
    }

    fn count(&self) -> usize {
        self.messages.lock().expect("lock").len()
    }
}

impl EmailSender for RecordingEmailSender {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        self.messages.lock().expect("lock").push(message.clone());
        Ok(())
    }
}

/// Test-only email sender that always fails. Used to validate that
/// downstream failures are surfaced without swallowing.
struct FailingEmailSender;

impl EmailSender for FailingEmailSender {
    fn send(&self, _message: &EmailMessage) -> Result<(), EmailError> {
        Err(EmailError::Transport {
            reason: "test-only failure".to_string(),
        })
    }
}

/// Bundles everything a test needs: engines, data dir, email recorder.
struct TestEnv {
    identity: Arc<dyn IdentityEngine>,
    authz: Arc<dyn RbacEngine>,
    email: Arc<RecordingEmailSender>,
    #[allow(dead_code)]
    email_service: Arc<EmailService>,
    service: Arc<OnboardingService>,
    temp: tempfile::TempDir,
}

impl TestEnv {
    fn new() -> Self {
        Self::with_email_sender(Arc::new(RecordingEmailSender::default()))
    }

    fn with_email_sender(email: Arc<RecordingEmailSender>) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let storage_cfg = StorageConfig::dev(temp.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(storage_cfg).expect("open storage"));
        let storage_dyn: Arc<dyn StorageEngine> = Arc::clone(&storage) as _;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let authz: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&storage_dyn),
            Arc::clone(&clock),
        ));
        let identity_cfg = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage_dyn),
            Arc::clone(&clock),
        ));
        let identity: Arc<dyn IdentityEngine> = Arc::new(
            EmbeddedIdentityEngine::new(
                Arc::clone(&storage_dyn),
                Arc::clone(&clock),
                identity_cfg,
                Arc::clone(&audit),
            )
            .expect("identity engine"),
        );
        let email_service = Arc::new(
            EmailService::new(
                Arc::clone(&email) as hearth::identity::SharedEmailSender,
                "Hearth".to_string(),
                None,
                EmailBranding::default(),
                String::new(),
                None,
            )
            .expect("email service"),
        );
        let service = Arc::new(OnboardingService::new(
            Arc::clone(&identity),
            Arc::clone(&authz),
            Arc::clone(&email_service),
            temp.path().to_path_buf(),
        ));
        Self {
            identity,
            authz,
            email,
            email_service,
            service,
            temp,
        }
    }

    fn data_dir(&self) -> &std::path::Path {
        self.temp.path()
    }

    fn setup_token_path(&self) -> std::path::PathBuf {
        self.data_dir().join(SETUP_TOKEN_FILENAME)
    }

    /// Pre-creates a realm so `complete_setup()` can find it.
    /// (In production, realm reconciliation from YAML does this at startup.)
    fn seed_realm(&self, name: &str) -> Realm {
        self.identity
            .create_realm(&CreateRealmRequest {
                name: name.to_string(),
                config: None,
            })
            .expect("seed realm")
    }
}

// ===== Scenario: first-run lifecycle =====

#[test]
fn is_first_run_flips_after_first_realm() {
    let env = TestEnv::new();
    assert!(is_first_run(env.identity.as_ref()).expect("first-run check"));

    env.identity
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: None,
        })
        .expect("create realm");

    assert!(!is_first_run(env.identity.as_ref()).expect("first-run check"));
}

#[test]
fn ensure_setup_token_creates_file_on_first_run() {
    let env = TestEnv::new();
    let token = ensure_setup_token(
        env.identity.as_ref(),
        env.data_dir(),
        Some("https://auth.example.com"),
        None,
        None,
    )
    .expect("ensure")
    .expect("token expected on first run");

    assert_eq!(token.len(), 43, "base64url(32 bytes) = 43 chars");
    assert!(env.setup_token_path().exists());
}

#[test]
fn ensure_setup_token_is_idempotent_on_restart() {
    let env = TestEnv::new();
    let a = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("first call")
        .expect("token");
    let b = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("second call")
        .expect("token");
    assert_eq!(a, b, "restart must not rotate an uncompleted setup token");
}

#[test]
fn ensure_setup_token_preserves_file_when_realms_exist() {
    let env = TestEnv::new();
    // Seed a token as if a previous startup generated it, then
    // reconciliation created a realm before setup was completed.
    std::fs::write(env.setup_token_path(), "existing-token").expect("seed");

    env.identity
        .create_realm(&CreateRealmRequest {
            name: "reconciled".to_string(),
            config: None,
        })
        .expect("create");

    // Token file is the source of truth — its presence means setup is
    // still in progress, regardless of realm count.
    let token = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token preserved when file exists");

    assert_eq!(token, "existing-token");
    assert!(
        env.setup_token_path().exists(),
        "token file must not be deleted"
    );
}

// ===== Scenario: setup-token validation =====

#[test]
fn consume_setup_token_accepts_matching_token() {
    let env = TestEnv::new();
    let token = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token");

    consume_setup_token(env.identity.as_ref(), env.data_dir(), &token).expect("match");
}

#[test]
fn consume_setup_token_rejects_mismatch() {
    let env = TestEnv::new();
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token");

    let err = consume_setup_token(env.identity.as_ref(), env.data_dir(), "wrong-token")
        .expect_err("mismatch");
    assert!(matches!(err, OnboardingError::InvalidSetupToken));
}

#[test]
fn consume_setup_token_rejects_when_file_absent() {
    let env = TestEnv::new();
    // No ensure_setup_token call — file does not exist.
    let err = consume_setup_token(env.identity.as_ref(), env.data_dir(), "whatever")
        .expect_err("no file");
    assert!(matches!(err, OnboardingError::InvalidSetupToken));
}

#[test]
fn consume_setup_token_accepts_when_realms_exist_and_file_present() {
    let env = TestEnv::new();
    let token = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token");

    // Simulate reconciliation creating a realm before setup completes.
    // The token file is the source of truth, not realm count.
    env.identity
        .create_realm(&CreateRealmRequest {
            name: "reconciled-default".to_string(),
            config: None,
        })
        .expect("create");

    consume_setup_token(env.identity.as_ref(), env.data_dir(), &token)
        .expect("token should still be valid — file exists and matches");
}

#[test]
fn setup_token_survives_realm_reconciliation() {
    let env = TestEnv::new();
    // Generate setup token on a fresh instance.
    let token = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token on fresh instance");

    // Simulate reconciliation creating a "default" realm.
    env.identity
        .create_realm(&CreateRealmRequest {
            name: "default".to_string(),
            config: None,
        })
        .expect("create realm");

    // Re-run ensure_setup_token (as happens on server restart). The token
    // file should still be returned — its presence is the source of truth,
    // not the realm count.
    let token2 = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure after reconciliation")
        .expect("token should survive");

    assert_eq!(token, token2, "token must be the same across restarts");

    // consume_setup_token should still work.
    consume_setup_token(env.identity.as_ref(), env.data_dir(), &token)
        .expect("token still valid after reconciliation");
}

// ===== Scenario: complete_setup happy path =====

#[test]
fn complete_setup_creates_admin_and_sends_email() {
    let env = TestEnv::new();
    // Mirrors real startup: ensure_setup_token runs first (fresh instance),
    // then realm reconciliation creates the realm from YAML.
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token");
    // Seeding an application realm is no longer required — admins live
    // in the auto-seeded system realm. We still create one to verify it
    // is *not* picked (regression test on the old behavior).
    let _ignored = env.seed_realm("hearth-prod");

    let pw = CleartextPassword::new(b"correct-horse-battery-staple".to_vec());
    let outcome = env
        .service
        .complete_setup(
            "admin@example.com",
            "Root Admin",
            &pw,
            "https://auth.example.com",
        )
        .expect("complete_setup");

    // Admin now lives in the system realm, not the YAML-declared app realm.
    assert_eq!(
        outcome.realm_id,
        hearth::core::RealmId::new(uuid::Uuid::nil()),
        "admin must land in the system realm"
    );
    let user = env
        .identity
        .get_user(&outcome.realm_id, &outcome.admin_user_id)
        .expect("get_user")
        .expect("user exists");
    assert_eq!(user.status(), UserStatus::PendingVerification);
    assert_eq!(user.email(), "admin@example.com");

    // Email sent once with a non-empty verification URL that routes
    // through the admin surface.
    assert_eq!(env.email.count(), 1);
    let msg = env.email.last().expect("email sent");
    assert_eq!(msg.to, "admin@example.com");
    assert!(
        msg.text_body.contains(&outcome.verification_url),
        "text body should contain verification URL: {}",
        msg.text_body
    );
    assert!(
        outcome
            .verification_url
            .starts_with("https://auth.example.com/ui/admin/verify-email?token="),
        "verification URL must target admin route: {}",
        outcome.verification_url
    );

    // realm.admin RBAC assignment was written.
    let resolved = env
        .authz
        .resolve_permissions(&outcome.admin_user_id, &outcome.realm_id, None, None)
        .expect("resolve permissions");
    assert!(
        resolved
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin"),
        "new admin should carry hearth.admin permission"
    );

    // Setup token is gone so the flow cannot be re-triggered.
    assert!(!env.setup_token_path().exists());
    assert!(!is_first_run(env.identity.as_ref()).expect("first-run check"));
}

// ===== Scenario: PendingVerification gating on sessions =====

#[test]
fn session_creation_blocked_for_pending_verification_user() {
    let env = TestEnv::new();
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None);
    env.seed_realm("RealmX");
    let pw = CleartextPassword::new(b"a-password".to_vec());
    let outcome = env
        .service
        .complete_setup(
            "pending@example.com",
            "Pending User",
            &pw,
            "http://localhost:8420",
        )
        .expect("complete_setup");

    let err = env
        .identity
        .create_session(
            &outcome.realm_id,
            &outcome.admin_user_id,
            &hearth::identity::SessionContext::default(),
        )
        .expect_err("pending user should not get a session");
    assert!(
        matches!(err, hearth::identity::IdentityError::UserNotVerified),
        "got {err:?}"
    );
}

// ===== Scenario: email verification activates the user =====

#[test]
fn verify_email_token_activates_user_and_unblocks_session() {
    let env = TestEnv::new();
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None);
    env.seed_realm("RealmY");
    let pw = CleartextPassword::new(b"another-password".to_vec());
    let outcome = env
        .service
        .complete_setup(
            "verify@example.com",
            "Verify Me",
            &pw,
            "http://localhost:8420",
        )
        .expect("complete_setup");

    // Extract the token from the verification URL embedded in the email.
    let msg = env.email.last().expect("email captured");
    let token = msg
        .text_body
        .split("token=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("token in text body")
        .to_string();

    let user_id = env
        .identity
        .verify_email_token(&outcome.realm_id, &token)
        .expect("verify");
    assert_eq!(user_id, outcome.admin_user_id);

    // Status transitioned.
    let user = env
        .identity
        .get_user(&outcome.realm_id, &outcome.admin_user_id)
        .expect("get_user")
        .expect("user");
    assert_eq!(user.status(), UserStatus::Active);

    // Sessions can now be created.
    env.identity
        .create_session(
            &outcome.realm_id,
            &outcome.admin_user_id,
            &hearth::identity::SessionContext::default(),
        )
        .expect("active user can create sessions");
}

#[test]
fn verify_email_token_rejects_reuse() {
    let env = TestEnv::new();
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None);
    env.seed_realm("RealmZ");
    let pw = CleartextPassword::new(b"pw".to_vec());
    let outcome = env
        .service
        .complete_setup("reuse@example.com", "Reuse", &pw, "http://localhost:8420")
        .expect("complete_setup");

    let msg = env.email.last().expect("email captured");
    let token = msg
        .text_body
        .split("token=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .expect("token in text body")
        .to_string();

    // First use succeeds.
    env.identity
        .verify_email_token(&outcome.realm_id, &token)
        .expect("first use ok");

    // Second use fails with the vague "invalid" error for enumeration resistance.
    let err = env
        .identity
        .verify_email_token(&outcome.realm_id, &token)
        .expect_err("reuse blocked");
    assert!(matches!(
        err,
        hearth::identity::IdentityError::VerificationTokenInvalid
    ));
}

#[test]
fn verify_email_token_rejects_unknown_token() {
    let env = TestEnv::new();
    let realm = env
        .identity
        .create_realm(&CreateRealmRequest {
            name: "other".to_string(),
            config: None,
        })
        .expect("create");

    let err = env
        .identity
        .verify_email_token(realm.id(), "not-a-real-token")
        .expect_err("unknown token rejected");
    assert!(matches!(
        err,
        hearth::identity::IdentityError::VerificationTokenInvalid
    ));
}

// ===== Scenario: complete_setup refuses when already configured =====

#[test]
fn complete_setup_refuses_when_setup_token_absent() {
    let env = TestEnv::new();
    env.seed_realm("pre-existing");

    // No ensure_setup_token call — the token file does not exist,
    // simulating a deployment where setup was already completed.
    let pw = CleartextPassword::new(b"pw".to_vec());
    let err = env
        .service
        .complete_setup("dup@example.com", "Dup", &pw, "http://localhost:8420")
        .expect_err("should refuse");
    assert!(
        matches!(err, OnboardingError::AlreadyConfigured),
        "got {err:?}"
    );
}

// ===== Scenario: complete_setup works even with no application realms =====
//
// Under the admin-realm architecture the system realm is auto-seeded at
// engine construction, so setup no longer depends on reconciliation
// having created any application realm. A deployment with zero declared
// realms can still complete setup and produce a usable admin.

#[test]
fn complete_setup_succeeds_without_app_realms() {
    let env = TestEnv::new();
    // No application realms created — reconciliation did not run.
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token");

    let pw = CleartextPassword::new(b"correct-horse-battery-staple".to_vec());
    let outcome = env
        .service
        .complete_setup("admin@example.com", "Admin", &pw, "http://localhost:8420")
        .expect("complete_setup");

    // Admin lives in the system realm (nil UUID).
    assert_eq!(
        outcome.realm_id,
        hearth::core::RealmId::new(uuid::Uuid::nil())
    );

    // Setup token has been retired so the flow cannot be re-triggered.
    assert!(!env.setup_token_path().exists());
}

// ===== Scenario: email failure is surfaced =====

#[test]
fn complete_setup_surfaces_email_delivery_failure() {
    let temp = tempfile::tempdir().expect("tempdir");
    let storage_cfg = StorageConfig::dev(temp.path().to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_cfg).expect("open storage"));
    let storage_dyn: Arc<dyn StorageEngine> = Arc::clone(&storage) as _;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let authz: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage_dyn),
        Arc::clone(&clock),
    ));
    let identity_cfg = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage_dyn),
        Arc::clone(&clock),
    ));
    let identity: Arc<dyn IdentityEngine> = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage_dyn),
            Arc::clone(&clock),
            identity_cfg,
            Arc::clone(&audit),
        )
        .expect("identity"),
    );
    let email_service = Arc::new(
        EmailService::new(
            Arc::new(FailingEmailSender) as hearth::identity::SharedEmailSender,
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let service = OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        email_service,
        temp.path().to_path_buf(),
    );

    // Seed the setup token first (mirrors real startup: ensure_setup_token
    // runs before realm reconciliation).
    let _ = ensure_setup_token(identity.as_ref(), temp.path(), None, None, None)
        .expect("ensure")
        .expect("token");

    // Pre-create a realm (in production, YAML reconciliation does this).
    identity
        .create_realm(&CreateRealmRequest {
            name: "T".to_string(),
            config: None,
        })
        .expect("seed realm");

    let pw = CleartextPassword::new(b"pw".to_vec());
    let err = service
        .complete_setup("boom@example.com", "B", &pw, "http://localhost:8420")
        .expect_err("email failure");
    assert!(
        matches!(err, OnboardingError::Email(_)),
        "expected Email(_), got {err:?}"
    );
    // The setup token is removed before email delivery because all critical
    // state (user, password, RBAC role assignment, verification token) is persisted
    // and the verification URL is logged. This prevents the "first-run setup
    // required" warning from firing on every restart.
    assert!(
        !temp.path().join(SETUP_TOKEN_FILENAME).exists(),
        "setup token must be removed even when email delivery fails"
    );
}

// ===== Scenario: ensure_setup_token email notification =====

#[test]
fn ensure_setup_token_sends_notification_email_when_configured() {
    let env = TestEnv::new();
    let recording_sender = Arc::new(RecordingEmailSender::default());
    let email_service = EmailService::new(
        Arc::clone(&recording_sender) as hearth::identity::SharedEmailSender,
        "Hearth".to_string(),
        None,
        EmailBranding::default(),
        String::new(),
        None,
    )
    .expect("email service");

    let token = ensure_setup_token(
        env.identity.as_ref(),
        env.data_dir(),
        Some("https://auth.example.com"),
        Some(&email_service),
        Some("ops@example.com"),
    )
    .expect("ensure")
    .expect("token on first run");

    assert_eq!(
        recording_sender.count(),
        1,
        "exactly one notification email sent"
    );
    let msg = recording_sender.last().expect("message recorded");
    assert_eq!(msg.to, "ops@example.com");
    assert!(
        msg.text_body.contains(&token),
        "notification text must contain the setup token: {}",
        msg.text_body
    );
}

/// When `base_url` is absent the emailed setup URL must still be absolute so
/// that operators on headless installs can navigate to it.
#[test]
fn ensure_setup_token_absolute_url_when_base_url_absent() {
    let env = TestEnv::new();
    let recording_sender = Arc::new(RecordingEmailSender::default());
    let email_service = EmailService::new(
        Arc::clone(&recording_sender) as hearth::identity::SharedEmailSender,
        "Hearth".to_string(),
        None,
        EmailBranding::default(),
        String::new(),
        None,
    )
    .expect("email service");

    ensure_setup_token(
        env.identity.as_ref(),
        env.data_dir(),
        None,
        Some(&email_service),
        Some("ops@example.com"),
    )
    .expect("ensure")
    .expect("token on first run");

    let msg = recording_sender.last().expect("message recorded");
    assert!(
        msg.text_body.contains("http://"),
        "setup URL must be absolute even when base_url is absent: {}",
        msg.text_body
    );
}

#[test]
fn ensure_setup_token_no_email_when_sender_absent() {
    let env = TestEnv::new();
    // notification_email is set but sender is None → no email, no panic
    let token = ensure_setup_token(
        env.identity.as_ref(),
        env.data_dir(),
        Some("https://auth.example.com"),
        None,
        Some("ops@example.com"),
    )
    .expect("ensure")
    .expect("token on first run");

    assert_eq!(token.len(), 43);
}

#[test]
fn ensure_setup_token_failing_email_is_non_fatal() {
    let env = TestEnv::new();
    let email_service = EmailService::new(
        Arc::new(FailingEmailSender) as hearth::identity::SharedEmailSender,
        "Hearth".to_string(),
        None,
        EmailBranding::default(),
        String::new(),
        None,
    )
    .expect("email service");

    // A failing email sender must not propagate as an error — ensure returns Ok.
    let token = ensure_setup_token(
        env.identity.as_ref(),
        env.data_dir(),
        Some("https://auth.example.com"),
        Some(&email_service),
        Some("ops@example.com"),
    )
    .expect("ensure must succeed even when email fails")
    .expect("token on first run");

    assert_eq!(
        token.len(),
        43,
        "token still generated despite email failure"
    );
}
