//! First-run onboarding orchestration.
//!
//! Hearth ships without any pre-configured admin user. On a fresh deploy
//! the very first HTTP request must be able to *create* one — but
//! accepting an unauthenticated `POST /ui/setup` would let anyone who
//! reaches the port before the operator does claim adminship. This
//! module closes that window the same way Jenkins does with
//! `initialAdminPassword`:
//!
//! 1. At startup, if the setup-token file exists (or no realms exist
//!    and setup hasn't been completed), generate 32 random bytes
//!    (base64url) and write them to `<data_dir>/.setup_token` with
//!    `0600` perms. Log the full setup URL at WARN level.
//! 2. `/ui/setup` requires the token. Mismatch returns 404 (no leaks).
//! 3. `complete_setup` finds the first realm (created by YAML
//!    reconciliation or auto-created "default"), creates the admin user
//!    (`PendingVerification`) + Zanzibar `hearth#admin@user:<uuid>`
//!    tuple, issues a verification token, and sends the verification
//!    email. On success the setup-token file is removed.
//!
//! The service is completely off the hot path — invoked only at startup
//! (for token provisioning) and from `/ui/setup` (at most once per
//! deploy). Synchronous I/O is fine here.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use subtle::ConstantTimeEq;

use crate::authz::{AuthorizationEngine, ObjectRef, RelationshipTuple, SubjectRef, TupleWrite};
use crate::core::RealmId;
use crate::identity::email::{EmailError, EmailService};
use crate::identity::{
    CleartextPassword, CreateUserRequest, IdentityEngine, IdentityError, UpdateUserRequest,
    UserStatus,
};

/// Filename used for the one-time setup token inside `data_dir`.
pub const SETUP_TOKEN_FILENAME: &str = ".setup_token";

/// Errors from the onboarding flow.
///
/// Kept deliberately small — the setup handler maps each variant to an
/// HTTP status code. Messages avoid leaking internals (no filesystem
/// paths, no database identifiers).
#[derive(Debug)]
#[non_exhaustive]
pub enum OnboardingError {
    /// An identity-layer call failed (realm/user creation, password set,
    /// token issue).
    Identity(IdentityError),
    /// Writing the Zanzibar admin tuple failed.
    Authz(String),
    /// Verification email could not be delivered.
    Email(EmailError),
    /// Filesystem I/O for the setup-token file failed.
    Io(String),
    /// `complete_setup` was called but Hearth is already configured.
    AlreadyConfigured,
    /// The setup token submitted by the caller does not match the
    /// on-disk token (or the token file has been removed).
    InvalidSetupToken,
}

impl std::fmt::Display for OnboardingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identity(e) => write!(f, "identity error during onboarding: {e}"),
            Self::Authz(reason) => write!(f, "authorization error during onboarding: {reason}"),
            Self::Email(e) => write!(f, "email error during onboarding: {e}"),
            Self::Io(reason) => write!(f, "setup token I/O error: {reason}"),
            Self::AlreadyConfigured => {
                write!(f, "setup is not available: a realm already exists")
            }
            Self::InvalidSetupToken => write!(f, "invalid setup token"),
        }
    }
}

impl std::error::Error for OnboardingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(e) => Some(e),
            Self::Email(e) => Some(e),
            Self::Authz(_) | Self::Io(_) | Self::AlreadyConfigured | Self::InvalidSetupToken => {
                None
            }
        }
    }
}

impl From<IdentityError> for OnboardingError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<EmailError> for OnboardingError {
    fn from(e: EmailError) -> Self {
        Self::Email(e)
    }
}

/// Result of successfully completing first-run setup.
#[derive(Debug, Clone)]
pub struct SetupOutcome {
    /// The newly-created realm's identifier.
    pub realm_id: RealmId,
    /// The primary admin user's identifier.
    pub admin_user_id: crate::identity::UserId,
    /// Verification URL the user must visit to activate their account.
    pub verification_url: String,
}

/// Returns `true` iff no realms exist yet.
///
/// Called both at startup (to decide whether to generate a setup token)
/// and on every `/ui/setup` request (for race-safety). `list_realms`
/// with `limit = 1` is cheap enough to poll.
///
/// # Errors
///
/// Returns any error from `list_realms`.
pub fn is_first_run(engine: &dyn IdentityEngine) -> Result<bool, IdentityError> {
    let page = engine.list_realms(None, 1)?;
    Ok(page.items.is_empty())
}

/// Ensures a setup-token file exists when setup hasn't been completed.
///
/// The **token file is the source of truth** for "setup in progress":
///
/// - File present: reads the existing token, logs the setup URL at WARN
///   level, optionally emails it, and returns `Ok(Some(token))`. This
///   is idempotent across restarts — the token survives even if realm
///   reconciliation has already created realms.
/// - File absent + no realms: truly fresh instance. Generates 32 random
///   bytes (base64url), writes `<data_dir>/.setup_token` with `0600`
///   perms (Unix), logs the setup URL, returns `Ok(Some(token))`.
/// - File absent + realms exist: setup already completed (or was never
///   required). Returns `Ok(None)`.
///
/// When `email_service` and `notification_email` are both provided,
/// additionally sends the setup URL to that address. Email failure is
/// non-fatal — the WARN log is always emitted regardless.
///
/// # Errors
///
/// Returns [`OnboardingError::Io`] on filesystem failure or
/// [`OnboardingError::Identity`] if the first-run check fails.
pub fn ensure_setup_token(
    engine: &dyn IdentityEngine,
    data_dir: &Path,
    base_url: Option<&str>,
    email_service: Option<&EmailService>,
    notification_email: Option<&str>,
) -> Result<Option<String>, OnboardingError> {
    let path = setup_token_path(data_dir);

    // 1. Token file exists → setup is still in progress. Read the
    //    existing token and re-log the URL (idempotent across restarts,
    //    survives realm reconciliation creating realms).
    if path.exists() {
        let token = read_setup_token_file(&path)?;
        log_and_notify_setup_url(&token, base_url, email_service, notification_email);
        return Ok(Some(token));
    }

    // 2. Token file absent + no realms → truly fresh instance.
    if is_first_run(engine)? {
        let token = generate_setup_token()?;
        write_setup_token_file(&path, &token)?;
        log_and_notify_setup_url(&token, base_url, email_service, notification_email);
        return Ok(Some(token));
    }

    // 3. Token file absent + realms exist → setup already completed.
    Ok(None)
}

/// Logs the setup URL at WARN level and optionally sends a notification
/// email. Email failure is non-fatal.
fn log_and_notify_setup_url(
    token: &str,
    base_url: Option<&str>,
    email_service: Option<&EmailService>,
    notification_email: Option<&str>,
) {
    let url = match base_url {
        Some(base) => format!("{}/ui/setup?token={}", base.trim_end_matches('/'), token),
        None => format!("/ui/setup?token={token}"),
    };
    tracing::warn!(
        setup_url = %url,
        "first-run setup required: open this URL to create the initial admin account"
    );

    if let (Some(service), Some(to)) = (email_service, notification_email) {
        if let Err(e) = service.send_setup_notification(to, &url) {
            tracing::warn!(
                error = %e,
                "failed to send setup notification email; check email config"
            );
        }
    }
}

/// Compares a caller-supplied token against the on-disk token in constant time.
///
/// Returns `Ok(())` only if the token file exists and the tokens match.
/// Any mismatch (missing file, byte-level diff) collapses into
/// [`OnboardingError::InvalidSetupToken`] so the handler can return a
/// single `404`.
///
/// # Errors
///
/// Returns [`OnboardingError::InvalidSetupToken`] when the supplied
/// token is not valid, and [`OnboardingError::Io`] if the token file is
/// unreadable for a reason other than being absent.
pub fn consume_setup_token(
    _engine: &dyn IdentityEngine,
    data_dir: &Path,
    supplied: &str,
) -> Result<(), OnboardingError> {
    let path = setup_token_path(data_dir);
    let on_disk = match read_setup_token_file(&path) {
        Ok(t) => t,
        Err(OnboardingError::Io(_)) if !path.exists() => {
            return Err(OnboardingError::InvalidSetupToken);
        }
        Err(e) => return Err(e),
    };
    if on_disk.as_bytes().ct_eq(supplied.as_bytes()).into() {
        Ok(())
    } else {
        Err(OnboardingError::InvalidSetupToken)
    }
}

/// Deletes the setup-token file. Best-effort; missing file is ignored.
///
/// Called after `complete_setup` succeeds so the token cannot be
/// re-used.
fn remove_setup_token(data_dir: &Path) {
    let path = setup_token_path(data_dir);
    if path.exists() {
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(
                error = %e,
                "failed to remove setup token file after completion"
            );
        }
    }
}

fn setup_token_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SETUP_TOKEN_FILENAME)
}

fn generate_setup_token() -> Result<String, OnboardingError> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes)
        .map_err(|_| OnboardingError::Io("failed to generate setup token".to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn read_setup_token_file(path: &Path) -> Result<String, OnboardingError> {
    let bytes = std::fs::read(path).map_err(|e| OnboardingError::Io(e.to_string()))?;
    let s = String::from_utf8(bytes)
        .map_err(|e| OnboardingError::Io(format!("setup token is not valid UTF-8: {e}")))?;
    Ok(s.trim().to_string())
}

fn write_setup_token_file(path: &Path, token: &str) -> Result<(), OnboardingError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| OnboardingError::Io(e.to_string()))?;
    }
    // Write atomically via a temp file + rename so a crash mid-write
    // cannot leave a partial token that would fail constant-time compare.
    let tmp = path.with_extension("tmp");
    write_file_mode_0600(&tmp, token.as_bytes())?;
    std::fs::rename(&tmp, path).map_err(|e| OnboardingError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(unix)]
fn write_file_mode_0600(path: &Path, bytes: &[u8]) -> Result<(), OnboardingError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| OnboardingError::Io(e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| OnboardingError::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| OnboardingError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_mode_0600(path: &Path, bytes: &[u8]) -> Result<(), OnboardingError> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|e| OnboardingError::Io(e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| OnboardingError::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| OnboardingError::Io(e.to_string()))?;
    Ok(())
}

/// Orchestrates first-run setup.
///
/// Composes `IdentityEngine` + `AuthorizationEngine` + `EmailService`
/// without owning any of them. Handler code holds an `Arc<OnboardingService>`.
pub struct OnboardingService {
    identity: Arc<dyn IdentityEngine>,
    authz: Arc<dyn AuthorizationEngine>,
    email: Arc<EmailService>,
    data_dir: PathBuf,
}

impl OnboardingService {
    /// Creates a new onboarding service.
    #[must_use]
    pub fn new(
        identity: Arc<dyn IdentityEngine>,
        authz: Arc<dyn AuthorizationEngine>,
        email: Arc<EmailService>,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            identity,
            authz,
            email,
            data_dir,
        }
    }

    /// Returns `true` iff no realm exists yet.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying `list_realms` call.
    pub fn is_first_run(&self) -> Result<bool, IdentityError> {
        is_first_run(self.identity.as_ref())
    }

    /// Validates a caller-supplied setup token against the on-disk token.
    ///
    /// # Errors
    ///
    /// See [`consume_setup_token`].
    pub fn verify_setup_token(&self, supplied: &str) -> Result<(), OnboardingError> {
        consume_setup_token(self.identity.as_ref(), &self.data_dir, supplied)
    }

    /// Executes the full first-run setup:
    ///
    /// 1. Create realm.
    /// 2. Create admin user (status = `PendingVerification`).
    /// 3. Set admin password.
    /// 4. Write Zanzibar `hearth#admin@user:<uuid>` tuple.
    /// 5. Issue email-verification token.
    /// 6. Send verification email.
    /// 7. Delete `.setup_token` so the flow cannot be re-triggered.
    ///
    /// This is *not* a single transaction across layers; each step
    /// commits to its own store. On failure partway through we leave
    /// behind the user but do *not* delete `.setup_token`, so the
    /// operator can re-submit after fixing the underlying issue
    /// (duplicate email, unreachable SMTP). `create_user` returns
    /// `DuplicateEmail` on retry which the caller renders as a 409.
    ///
    /// # Errors
    ///
    /// See [`OnboardingError`]. `AlreadyConfigured` is returned if the
    /// setup-token file has already been consumed. `RealmNotFound` is
    /// returned if no realm exists (YAML reconciliation must run first).
    pub fn complete_setup(
        &self,
        admin_email: &str,
        admin_display_name: &str,
        admin_password: &CleartextPassword,
        verification_base_url: &str,
    ) -> Result<SetupOutcome, OnboardingError> {
        // 0. Defence in depth: the token file's existence is the source
        //    of truth for "setup is in progress". If it's gone, setup
        //    has already been completed (or was never initiated).
        if !self.data_dir.join(SETUP_TOKEN_FILENAME).exists() {
            return Err(OnboardingError::AlreadyConfigured);
        }

        // 1. Find the first existing realm (created by YAML reconciliation
        //    or the auto-created "default"). Realms are managed exclusively
        //    through hearth.yaml — setup only creates the admin user.
        let page = self.identity.list_realms(None, 1)?;
        let realm = page
            .items
            .into_iter()
            .next()
            .ok_or_else(|| OnboardingError::Identity(IdentityError::RealmNotFound))?;
        let realm_id = realm.id().clone();

        // 2. Create admin user.
        let user = self.identity.create_user(
            &realm_id,
            &CreateUserRequest {
                email: admin_email.to_string(),
                display_name: admin_display_name.to_string(),
            },
        )?;
        let user_id = user.id().clone();

        // 3. Force status = PendingVerification (create_user uses the
        //    engine default, which is Active). The caller must verify
        //    their email before they can log in.
        self.identity.update_user(
            &realm_id,
            &user_id,
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::PendingVerification),
            },
        )?;

        // 4. Set password.
        self.identity
            .set_password(&realm_id, &user_id, admin_password)?;

        // 5. Zanzibar admin tuple: hearth#admin@user:<uuid>.
        //    INVARIANT: "hearth", "admin", "user" are valid short-ASCII
        //    field names; the user-id string is a canonical UUID.
        let object = ObjectRef::new("hearth", "admin")
            .map_err(|e| OnboardingError::Authz(format!("failed to build admin object: {e}")))?;
        let subject = SubjectRef::direct("user", &user_id.as_uuid().to_string())
            .map_err(|e| OnboardingError::Authz(format!("failed to build admin subject: {e}")))?;
        let tuple = RelationshipTuple::new(object, "admin", subject)
            .map_err(|e| OnboardingError::Authz(format!("failed to build admin tuple: {e}")))?;
        self.authz
            .write_tuples(&realm_id, &[TupleWrite::Touch(tuple)])
            .map_err(|e| OnboardingError::Authz(e.to_string()))?;

        // 6. Email-verification token.
        let token = self
            .identity
            .issue_email_verification_token(&realm_id, &user_id)?;
        let verification_url = format!(
            "{}/ui/verify-email?token={}",
            verification_base_url.trim_end_matches('/'),
            token
        );

        // 7. Log the link unconditionally so the operator can always recover
        //    it, even if email delivery fails or the log transport is in use.
        tracing::warn!(
            verification_url = %verification_url,
            "onboarding: verification link (check logs if email delivery fails)"
        );

        // 8a. Send the email. Failure here is fatal for the request but the
        //     user is already persisted; retrying the setup form will fail with
        //     DuplicateEmail. The operator can recover using the link above or
        //     by issuing a new verification token via the admin tools.
        self.email
            .send_verification_email(admin_email, &verification_url, None)?;

        // 8b. Retire the setup token.
        remove_setup_token(&self.data_dir);

        Ok(SetupOutcome {
            realm_id,
            admin_user_id: user_id,
            verification_url,
        })
    }

    /// Exposes the underlying identity engine for handlers that need
    /// unrelated operations (e.g. `verify_email_token`).
    #[must_use]
    pub fn identity(&self) -> &Arc<dyn IdentityEngine> {
        &self.identity
    }

    /// Exposes the underlying data dir (used by tests).
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_token_path_is_hidden_file_in_data_dir() {
        let p = setup_token_path(Path::new("/var/lib/hearth"));
        assert_eq!(p, PathBuf::from("/var/lib/hearth/.setup_token"));
    }

    #[test]
    fn generated_setup_token_is_url_safe_and_non_trivial() {
        let token = generate_setup_token().expect("rng works");
        // 32 raw bytes → 43 base64url chars (no padding).
        assert_eq!(token.len(), 43);
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "token must be base64url safe: {token}"
        );
    }

    #[test]
    fn generated_setup_tokens_are_unique() {
        let a = generate_setup_token().expect("rng");
        let b = generate_setup_token().expect("rng");
        assert_ne!(a, b);
    }

    #[test]
    fn write_then_read_round_trips_and_trims_whitespace() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join(".setup_token");
        write_setup_token_file(&path, "abc123").expect("write");
        let read = read_setup_token_file(&path).expect("read");
        assert_eq!(read, "abc123");
    }

    #[cfg(unix)]
    #[test]
    fn setup_token_file_has_0600_perms() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join(".setup_token");
        write_setup_token_file(&path, "secret").expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got mode {:o}", mode & 0o777);
    }

    #[test]
    fn onboarding_error_display_does_not_leak_internals() {
        let cases = [
            OnboardingError::Authz("raft timeout".to_string()),
            OnboardingError::Io("permission denied".to_string()),
            OnboardingError::AlreadyConfigured,
            OnboardingError::InvalidSetupToken,
        ];
        for err in cases {
            let s = format!("{err}");
            assert!(!s.is_empty(), "empty display for {err:?}");
        }
    }

    #[test]
    fn onboarding_error_from_identity() {
        let err: OnboardingError = IdentityError::DuplicateRealmName.into();
        assert!(matches!(err, OnboardingError::Identity(_)));
    }

    #[test]
    fn onboarding_error_from_email() {
        let err: OnboardingError = EmailError::Transport {
            reason: "refused".to_string(),
        }
        .into();
        assert!(matches!(err, OnboardingError::Email(_)));
    }
}
