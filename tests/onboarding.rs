//! Integration tests for production onboarding (Phase 1.5 / Step 32).
//!
//! Covers `TEST_SCENARIOS.md` § Onboarding (Setup + Email Verification):
//! - First-run detection toggles when the first tenant is created.
//! - Setup-token lifecycle: generated once, consumed on success, removed
//!   automatically when the deployment becomes configured.
//! - Full setup flow: tenant + admin (`PendingVerification`) + Zanzibar
//!   admin tuple + verification token + verification email.
//! - Session creation is gated on `UserStatus::Active`; a
//!   `PendingVerification` user cannot create sessions.
//! - Verification-token reuse, expiry, and enumeration-resistance.
//!
//! The tests build their own engine stack rather than going through
//! `TestHarness` because `OnboardingService` requires `Arc<dyn Trait>`
//! handles and the harness exposes trait references.

use std::sync::{Arc, Mutex};

use hearth::authz::{AuthorizationEngine, AuthzConfig, EmbeddedAuthzEngine, ObjectRef, SubjectRef};
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::{EmailError, EmailSender};
use hearth::identity::onboarding::{
    consume_setup_token, ensure_setup_token, is_first_run, OnboardingError, OnboardingService,
    SETUP_TOKEN_FILENAME,
};
use hearth::identity::{
    CleartextPassword, CreateTenantRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, UserStatus,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Test-only email sender that records every sent message.
#[derive(Default)]
struct RecordingEmailSender {
    messages: Mutex<Vec<(String, String)>>,
}

impl RecordingEmailSender {
    fn last(&self) -> Option<(String, String)> {
        self.messages.lock().expect("lock").last().cloned()
    }

    fn count(&self) -> usize {
        self.messages.lock().expect("lock").len()
    }
}

impl EmailSender for RecordingEmailSender {
    fn send_verification_email(&self, to: &str, verification_url: &str) -> Result<(), EmailError> {
        self.messages
            .lock()
            .expect("lock")
            .push((to.to_string(), verification_url.to_string()));
        Ok(())
    }

    fn send_setup_notification(&self, to: &str, setup_url: &str) -> Result<(), EmailError> {
        self.messages
            .lock()
            .expect("lock")
            .push((to.to_string(), setup_url.to_string()));
        Ok(())
    }
}

/// Test-only email sender that always fails. Used to validate that
/// downstream failures are surfaced without swallowing.
struct FailingEmailSender;

impl EmailSender for FailingEmailSender {
    fn send_verification_email(
        &self,
        _to: &str,
        _verification_url: &str,
    ) -> Result<(), EmailError> {
        Err(EmailError::Transport {
            reason: "test-only failure".to_string(),
        })
    }

    fn send_setup_notification(&self, _to: &str, _setup_url: &str) -> Result<(), EmailError> {
        Err(EmailError::Transport {
            reason: "test-only failure".to_string(),
        })
    }
}

/// Bundles everything a test needs: engines, data dir, email recorder.
struct TestEnv {
    identity: Arc<dyn IdentityEngine>,
    authz: Arc<dyn AuthorizationEngine>,
    email: Arc<RecordingEmailSender>,
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
        let authz: Arc<dyn AuthorizationEngine> = Arc::new(EmbeddedAuthzEngine::new(
            Arc::clone(&storage_dyn),
            AuthzConfig::default(),
        ));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let identity_cfg = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let identity: Arc<dyn IdentityEngine> = Arc::new(
            EmbeddedIdentityEngine::new(Arc::clone(&storage_dyn), clock, identity_cfg)
                .expect("identity engine"),
        );
        let email_dyn: hearth::identity::SharedEmailSender =
            Arc::clone(&email) as Arc<dyn EmailSender>;
        let service = Arc::new(OnboardingService::new(
            Arc::clone(&identity),
            Arc::clone(&authz),
            email_dyn,
            temp.path().to_path_buf(),
        ));
        Self {
            identity,
            authz,
            email,
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
}

// ===== Scenario: first-run lifecycle =====

#[test]
fn is_first_run_flips_after_first_tenant() {
    let env = TestEnv::new();
    assert!(is_first_run(env.identity.as_ref()).expect("first-run check"));

    env.identity
        .create_tenant(&CreateTenantRequest {
            name: "acme".to_string(),
            config: None,
        })
        .expect("create tenant");

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
fn ensure_setup_token_removes_stale_token_when_configured() {
    let env = TestEnv::new();
    // Seed as if a previous incarnation left a token behind.
    std::fs::write(env.setup_token_path(), "stale").expect("seed");

    // Now configure the system.
    env.identity
        .create_tenant(&CreateTenantRequest {
            name: "existing".to_string(),
            config: None,
        })
        .expect("create");

    let result =
        ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
            .expect("ensure");

    assert!(result.is_none(), "not first-run → None");
    assert!(
        !env.setup_token_path().exists(),
        "stale token must be cleaned up"
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
fn consume_setup_token_rejects_after_system_is_configured() {
    let env = TestEnv::new();
    let token = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token");

    // Someone else races and creates a tenant out-of-band.
    env.identity
        .create_tenant(&CreateTenantRequest {
            name: "first-winner".to_string(),
            config: None,
        })
        .expect("create");

    let err = consume_setup_token(env.identity.as_ref(), env.data_dir(), &token)
        .expect_err("already configured");
    assert!(matches!(err, OnboardingError::InvalidSetupToken));
}

// ===== Scenario: complete_setup happy path =====

#[test]
fn complete_setup_creates_tenant_admin_and_sends_email() {
    let env = TestEnv::new();
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None)
        .expect("ensure")
        .expect("token");

    let pw = CleartextPassword::new(b"correct-horse-battery-staple".to_vec());
    let outcome = env
        .service
        .complete_setup(
            "Hearth Prod",
            "admin@example.com",
            "Root Admin",
            &pw,
            "https://auth.example.com",
        )
        .expect("complete_setup");

    // Tenant + admin exist.
    let tenant = env
        .identity
        .get_tenant(&outcome.tenant_id)
        .expect("get_tenant")
        .expect("tenant exists");
    assert_eq!(tenant.name(), "Hearth Prod");

    let user = env
        .identity
        .get_user(&outcome.tenant_id, &outcome.admin_user_id)
        .expect("get_user")
        .expect("user exists");
    assert_eq!(user.status(), UserStatus::PendingVerification);
    assert_eq!(user.email(), "admin@example.com");

    // Email sent once with a non-empty verification URL.
    assert_eq!(env.email.count(), 1);
    let (to, url) = env.email.last().expect("email sent");
    assert_eq!(to, "admin@example.com");
    assert!(url.starts_with("https://auth.example.com/ui/verify-email?token="));
    assert_eq!(url, outcome.verification_url);

    // Zanzibar admin tuple was written.
    let admin_object = ObjectRef::new("hearth", "admin").expect("object");
    let admin_subject =
        SubjectRef::direct("user", &outcome.admin_user_id.as_uuid().to_string()).expect("subject");
    let allowed = env
        .authz
        .check(
            &outcome.tenant_id,
            &admin_object,
            "admin",
            &admin_subject,
            None,
        )
        .expect("check");
    assert!(allowed, "new admin should pass hearth#admin check");

    // Setup token is gone so the flow cannot be re-triggered.
    assert!(!env.setup_token_path().exists());
    assert!(!is_first_run(env.identity.as_ref()).expect("first-run check"));
}

// ===== Scenario: PendingVerification gating on sessions =====

#[test]
fn session_creation_blocked_for_pending_verification_user() {
    let env = TestEnv::new();
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None);
    let pw = CleartextPassword::new(b"a-password".to_vec());
    let outcome = env
        .service
        .complete_setup(
            "TenantX",
            "pending@example.com",
            "Pending User",
            &pw,
            "http://localhost:8420",
        )
        .expect("complete_setup");

    let err = env
        .identity
        .create_session(&outcome.tenant_id, &outcome.admin_user_id)
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
    let pw = CleartextPassword::new(b"another-password".to_vec());
    let outcome = env
        .service
        .complete_setup(
            "TenantY",
            "verify@example.com",
            "Verify Me",
            &pw,
            "http://localhost:8420",
        )
        .expect("complete_setup");

    // Extract the token from the sent email URL.
    let (_, url) = env.email.last().expect("email captured");
    let token = url.split("token=").nth(1).expect("token query").to_string();

    let user_id = env
        .identity
        .verify_email_token(&outcome.tenant_id, &token)
        .expect("verify");
    assert_eq!(user_id, outcome.admin_user_id);

    // Status transitioned.
    let user = env
        .identity
        .get_user(&outcome.tenant_id, &outcome.admin_user_id)
        .expect("get_user")
        .expect("user");
    assert_eq!(user.status(), UserStatus::Active);

    // Sessions can now be created.
    env.identity
        .create_session(&outcome.tenant_id, &outcome.admin_user_id)
        .expect("active user can create sessions");
}

#[test]
fn verify_email_token_rejects_reuse() {
    let env = TestEnv::new();
    let _ = ensure_setup_token(env.identity.as_ref(), env.data_dir(), None, None, None);
    let pw = CleartextPassword::new(b"pw".to_vec());
    let outcome = env
        .service
        .complete_setup(
            "TenantZ",
            "reuse@example.com",
            "Reuse",
            &pw,
            "http://localhost:8420",
        )
        .expect("complete_setup");

    let (_, url) = env.email.last().expect("email captured");
    let token = url.split("token=").nth(1).expect("token").to_string();

    // First use succeeds.
    env.identity
        .verify_email_token(&outcome.tenant_id, &token)
        .expect("first use ok");

    // Second use fails with the vague "invalid" error for enumeration resistance.
    let err = env
        .identity
        .verify_email_token(&outcome.tenant_id, &token)
        .expect_err("reuse blocked");
    assert!(matches!(
        err,
        hearth::identity::IdentityError::VerificationTokenInvalid
    ));
}

#[test]
fn verify_email_token_rejects_unknown_token() {
    let env = TestEnv::new();
    let tenant = env
        .identity
        .create_tenant(&CreateTenantRequest {
            name: "other".to_string(),
            config: None,
        })
        .expect("create");

    let err = env
        .identity
        .verify_email_token(tenant.id(), "not-a-real-token")
        .expect_err("unknown token rejected");
    assert!(matches!(
        err,
        hearth::identity::IdentityError::VerificationTokenInvalid
    ));
}

// ===== Scenario: complete_setup refuses when already configured =====

#[test]
fn complete_setup_refuses_when_tenant_already_exists() {
    let env = TestEnv::new();
    env.identity
        .create_tenant(&CreateTenantRequest {
            name: "pre-existing".to_string(),
            config: None,
        })
        .expect("pre-existing tenant");

    let pw = CleartextPassword::new(b"pw".to_vec());
    let err = env
        .service
        .complete_setup(
            "Dup",
            "dup@example.com",
            "Dup",
            &pw,
            "http://localhost:8420",
        )
        .expect_err("should refuse");
    assert!(
        matches!(err, OnboardingError::AlreadyConfigured),
        "got {err:?}"
    );
}

// ===== Scenario: email failure is surfaced =====

#[test]
fn complete_setup_surfaces_email_delivery_failure() {
    let temp = tempfile::tempdir().expect("tempdir");
    let storage_cfg = StorageConfig::dev(temp.path().to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_cfg).expect("open storage"));
    let storage_dyn: Arc<dyn StorageEngine> = Arc::clone(&storage) as _;
    let authz: Arc<dyn AuthorizationEngine> = Arc::new(EmbeddedAuthzEngine::new(
        Arc::clone(&storage_dyn),
        AuthzConfig::default(),
    ));
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let identity_cfg = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let identity: Arc<dyn IdentityEngine> =
        Arc::new(EmbeddedIdentityEngine::new(storage_dyn, clock, identity_cfg).expect("identity"));
    let email: hearth::identity::SharedEmailSender = Arc::new(FailingEmailSender);
    let service = OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        email,
        temp.path().to_path_buf(),
    );

    // Seed the setup token so the "keep on failure" assertion below is
    // meaningful — otherwise the file never existed to begin with.
    let _ = ensure_setup_token(identity.as_ref(), temp.path(), None, None, None)
        .expect("ensure")
        .expect("token");

    let pw = CleartextPassword::new(b"pw".to_vec());
    let err = service
        .complete_setup("T", "boom@example.com", "B", &pw, "http://localhost:8420")
        .expect_err("email failure");
    assert!(
        matches!(err, OnboardingError::Email(_)),
        "expected Email(_), got {err:?}"
    );
    // The failure leaves the setup token in place so the operator can retry.
    assert!(
        temp.path().join(SETUP_TOKEN_FILENAME).exists(),
        "setup token must persist when email delivery fails so operator can retry"
    );
}

// ===== Scenario: ensure_setup_token email notification =====

#[test]
fn ensure_setup_token_sends_notification_email_when_configured() {
    let env = TestEnv::new();
    let sender = Arc::new(RecordingEmailSender::default());

    let token = ensure_setup_token(
        env.identity.as_ref(),
        env.data_dir(),
        Some("https://auth.example.com"),
        Some(sender.as_ref()),
        Some("ops@example.com"),
    )
    .expect("ensure")
    .expect("token on first run");

    assert_eq!(sender.count(), 1, "exactly one notification email sent");
    let (to, url) = sender.last().expect("message recorded");
    assert_eq!(to, "ops@example.com");
    assert!(
        url.contains(&token),
        "notification URL must contain the setup token: {url}"
    );
    assert!(
        url.starts_with("https://auth.example.com/ui/setup?token="),
        "unexpected URL: {url}"
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
    let sender = FailingEmailSender;

    // A failing email sender must not propagate as an error — ensure returns Ok.
    let token = ensure_setup_token(
        env.identity.as_ref(),
        env.data_dir(),
        Some("https://auth.example.com"),
        Some(&sender),
        Some("ops@example.com"),
    )
    .expect("ensure must succeed even when email fails")
    .expect("token on first run");

    assert_eq!(token.len(), 43, "token still generated despite email failure");
}
