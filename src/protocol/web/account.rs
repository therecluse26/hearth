//! Axum handlers for the `/ui/account/*` self-service surface.
//!
//! Scope: signed-in users managing their own account. Each handler
//! requires a valid [`super::auth::UiSession`] — no admin role is
//! needed. Mutations go through [`IdentityEngine`] with audit trails
//! appended for every password change.
//!
//! # Routes covered here
//!
//! * `GET  /ui/account` — account index (password form, MFA state,
//!   passkey listing, links to sessions).
//! * `POST /ui/account/password` — change password.
//! * `GET  /ui/account/totp` — MFA enrol/disable page.
//! * `POST /ui/account/totp/activate` — verify the pending TOTP code
//!   and enable MFA.
//! * `POST /ui/account/totp/disable` — disable MFA.
//!
//! Passkey enrolment and session management live alongside in later
//! additions to this module.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::identity::{CleartextPassword, IdentityError};

use super::auth::{verify_csrf_form_field, UiSession};
use super::templates::{render, Flash};
use super::WebState;

// ---------------------------------------------------------------------------
// Account index
// ---------------------------------------------------------------------------

/// Template rendered by `GET /ui/account` and by POST handlers that
/// re-render the index with a flash message.
#[derive(Template)]
#[template(path = "ui/account/index.html")]
#[allow(clippy::struct_excessive_bools)] // layout/chrome flags are unavoidable here
struct AccountIndexTemplate {
    /// Change-password form error (for inline display above the form).
    password_error: Option<String>,
    /// Whether MFA is currently enabled on the signed-in user.
    mfa_enabled: bool,
    // Chrome/layout fields.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
}

impl AccountIndexTemplate {
    fn new(
        session: &UiSession,
        mfa_enabled: bool,
        flash: Option<Flash>,
        password_error: Option<String>,
        is_admin: bool,
    ) -> Self {
        Self {
            password_error,
            mfa_enabled,
            chrome: true,
            active: "account",
            user_email: Some(session.user_email.clone()),
            is_admin,
            flash,
            csrf: session.csrf.clone(),
            narrow: true,
        }
    }
}

/// Renders the `My Account` page for the signed-in user.
pub async fn account_index(State(state): State<Arc<WebState>>, session: UiSession) -> Response {
    let mfa_enabled = state
        .identity
        .mfa_enabled(&session.tenant_id, &session.user_id)
        .unwrap_or(false);
    let admin = super::handlers::is_admin(&state, &session);
    render(&AccountIndexTemplate::new(
        &session,
        mfa_enabled,
        None,
        None,
        admin,
    ))
}

// ---------------------------------------------------------------------------
// Change password
// ---------------------------------------------------------------------------

/// `application/x-www-form-urlencoded` body for `POST /ui/account/password`.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordForm {
    /// Current password (verified before applying the change).
    #[serde(default)]
    pub current_password: String,
    /// New password (minimum length is enforced by the identity engine).
    #[serde(default)]
    pub new_password: String,
    /// Client-side confirmation of the new password. Must match.
    #[serde(default)]
    pub confirm_password: String,
    /// CSRF double-submit token (matches the `hearth_ui_csrf` cookie).
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// Handles `POST /ui/account/password`.
///
/// On success: re-renders the index with a success flash.
/// On failure: re-renders the index with an inline error above the form.
pub async fn account_change_password(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    // Client-side mismatch check comes before any engine call so we
    // don't exercise the password verifier needlessly.
    if form.new_password != form.confirm_password {
        return render_with_password_error(
            &state,
            &session,
            "New password and confirmation do not match.",
        );
    }

    let current = CleartextPassword::from_string(form.current_password);
    let new_pw = CleartextPassword::from_string(form.new_password);

    match state
        .identity
        .change_password(&session.tenant_id, &session.user_id, &current, &new_pw)
    {
        Ok(()) => {
            // Audit the change (best-effort — never block the response).
            if let Err(e) = audit_password_changed(&state, &session) {
                tracing::warn!(error = %e, "account password change audit append failed");
            }
            render_with_flash(&state, &session, Flash::success("Password changed."))
        }
        Err(IdentityError::InvalidCredential { .. }) => {
            render_with_password_error(&state, &session, "Current password is incorrect.")
        }
        Err(IdentityError::InvalidInput { reason }) => {
            render_with_password_error(&state, &session, &reason)
        }
        Err(e) => {
            tracing::warn!(error = %e, "change_password failed");
            render_with_password_error(&state, &session, "Unable to change password right now.")
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Redirect used by the top-level layout after any mutation. Kept
/// private because handlers always want the PRG pattern only after
/// success — failure re-renders inline.
#[allow(dead_code)]
fn redirect_to_account() -> Response {
    Redirect::to("/ui/account").into_response()
}

/// Renders the account index with an inline password-form error.
fn render_with_password_error(state: &Arc<WebState>, session: &UiSession, msg: &str) -> Response {
    let mfa_enabled = state
        .identity
        .mfa_enabled(&session.tenant_id, &session.user_id)
        .unwrap_or(false);
    let admin = super::handlers::is_admin(state, session);
    render(&AccountIndexTemplate::new(
        session,
        mfa_enabled,
        None,
        Some(msg.to_string()),
        admin,
    ))
}

/// Renders the account index with a flash banner (used on success).
fn render_with_flash(state: &Arc<WebState>, session: &UiSession, flash: Flash) -> Response {
    let mfa_enabled = state
        .identity
        .mfa_enabled(&session.tenant_id, &session.user_id)
        .unwrap_or(false);
    let admin = super::handlers::is_admin(state, session);
    render(&AccountIndexTemplate::new(
        session,
        mfa_enabled,
        Some(flash),
        None,
        admin,
    ))
}

/// Appends a `credential.changed` event to the audit log. The event
/// is best-effort — failure is logged and does not fail the response.
fn audit_password_changed(
    state: &Arc<WebState>,
    session: &UiSession,
) -> Result<(), crate::audit::AuditError> {
    use crate::audit::{AuditAction, CreateAuditEvent};
    state.audit.append(&CreateAuditEvent {
        tenant_id: session.tenant_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action: AuditAction::CredentialChanged,
        resource_type: "user".to_string(),
        resource_id: session.user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// TOTP / MFA enrolment
// ---------------------------------------------------------------------------

/// Template rendered by `GET /ui/account/totp`.
///
/// When MFA is already enabled the template shows a disable form; when
/// it is not, the enrolment copy (secret, recovery codes, activation
/// form) is displayed.
#[derive(Template)]
#[template(path = "ui/account/totp.html")]
#[allow(clippy::struct_excessive_bools)] // layout/chrome flags are unavoidable here
struct TotpEnrollTemplate {
    /// Whether MFA is currently enabled.
    mfa_enabled: bool,
    /// Base32-encoded pending secret (only meaningful when `!mfa_enabled`).
    secret_base32: String,
    /// `otpauth://` URI for authenticator apps (only when `!mfa_enabled`).
    provisioning_uri: String,
    /// Plaintext recovery codes shown once (only when `!mfa_enabled`).
    recovery_codes: Vec<String>,
    /// Inline error shown above the activation form (e.g. "Invalid code").
    activation_error: Option<String>,
    // Chrome/layout fields.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
}

impl TotpEnrollTemplate {
    fn new(
        session: &UiSession,
        mfa_enabled: bool,
        secret_base32: String,
        provisioning_uri: String,
        recovery_codes: Vec<String>,
        activation_error: Option<String>,
        is_admin: bool,
    ) -> Self {
        Self {
            mfa_enabled,
            secret_base32,
            provisioning_uri,
            recovery_codes,
            activation_error,
            chrome: true,
            active: "account",
            user_email: Some(session.user_email.clone()),
            is_admin,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
        }
    }
}

/// `GET /ui/account/totp`.
///
/// If MFA is already enabled, renders the disable form. Otherwise
/// generates a fresh pending enrolment (secret + recovery codes) and
/// shows the scan-and-activate flow. Note that refreshing the page
/// rotates the pending secret — the user should complete enrolment
/// within a single session.
pub async fn totp_enroll_form(State(state): State<Arc<WebState>>, session: UiSession) -> Response {
    let admin = super::handlers::is_admin(&state, &session);
    let enabled = state
        .identity
        .mfa_enabled(&session.tenant_id, &session.user_id)
        .unwrap_or(false);

    if enabled {
        return render(&TotpEnrollTemplate::new(
            &session,
            true,
            String::new(),
            String::new(),
            Vec::new(),
            None,
            admin,
        ));
    }

    match state
        .identity
        .enroll_totp(&session.tenant_id, &session.user_id)
    {
        Ok(enrollment) => render(&TotpEnrollTemplate::new(
            &session,
            false,
            enrollment.secret_base32,
            enrollment.provisioning_uri,
            enrollment.recovery_codes.as_slice().to_vec(),
            None,
            admin,
        )),
        Err(IdentityError::MfaAlreadyEnabled) => render(&TotpEnrollTemplate::new(
            &session,
            true,
            String::new(),
            String::new(),
            Vec::new(),
            None,
            admin,
        )),
        Err(e) => {
            tracing::warn!(error = %e, "enroll_totp failed");
            render(&TotpEnrollTemplate::new(
                &session,
                false,
                String::new(),
                String::new(),
                Vec::new(),
                Some("Unable to start MFA enrolment right now.".to_string()),
                admin,
            ))
        }
    }
}

/// `application/x-www-form-urlencoded` body for `POST /ui/account/totp/activate`.
#[derive(Debug, Deserialize)]
pub struct ActivateTotpForm {
    /// Current TOTP code from the authenticator app.
    #[serde(default)]
    pub code: String,
    /// CSRF double-submit token.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/account/totp/activate`.
pub async fn totp_activate(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    Form(form): Form<ActivateTotpForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    match state.identity.verify_totp_enrollment(
        &session.tenant_id,
        &session.user_id,
        form.code.trim(),
    ) {
        Ok(()) => {
            if let Err(e) = audit_mfa_event(&state, &session, "mfa_enable") {
                tracing::warn!(error = %e, "totp enable audit append failed");
            }
            Redirect::to("/ui/account").into_response()
        }
        Err(IdentityError::InvalidMfaCode) => {
            render_totp_error(&state, &session, "Invalid authentication code.")
        }
        Err(IdentityError::MfaNotEnabled) => {
            // The pending secret was cleared somehow — send the user
            // back to the enrol page to start a fresh ceremony.
            Redirect::to("/ui/account/totp").into_response()
        }
        Err(IdentityError::MfaAlreadyEnabled) => Redirect::to("/ui/account").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "verify_totp_enrollment failed");
            render_totp_error(&state, &session, "Unable to activate MFA right now.")
        }
    }
}

/// `application/x-www-form-urlencoded` body for `POST /ui/account/totp/disable`.
#[derive(Debug, Deserialize)]
pub struct DisableTotpForm {
    /// CSRF double-submit token.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/account/totp/disable`.
pub async fn totp_disable(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    Form(form): Form<DisableTotpForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    match state
        .identity
        .disable_mfa(&session.tenant_id, &session.user_id)
    {
        Ok(()) | Err(IdentityError::MfaNotEnabled) => {
            if let Err(e) = audit_mfa_event(&state, &session, "mfa_disable") {
                tracing::warn!(error = %e, "totp disable audit append failed");
            }
            Redirect::to("/ui/account").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "disable_mfa failed");
            render_totp_error(&state, &session, "Unable to disable MFA right now.")
        }
    }
}

/// Re-renders the TOTP enrolment page with an inline error above the
/// activation form. Used when activation fails without restarting the
/// ceremony.
fn render_totp_error(state: &Arc<WebState>, session: &UiSession, msg: &str) -> Response {
    let admin = super::handlers::is_admin(state, session);
    let enabled = state
        .identity
        .mfa_enabled(&session.tenant_id, &session.user_id)
        .unwrap_or(false);

    // When enabled = true the activation form is not shown; in that
    // case there's no meaningful surface for an inline error, so we
    // fall through to rendering the disable form cleanly.
    if enabled {
        return render(&TotpEnrollTemplate::new(
            session,
            true,
            String::new(),
            String::new(),
            Vec::new(),
            None,
            admin,
        ));
    }

    // Render with empty secret/codes because regenerating would
    // invalidate the user's just-scanned QR. They can refresh to
    // restart if they need new recovery codes.
    render(&TotpEnrollTemplate::new(
        session,
        false,
        String::new(),
        String::new(),
        Vec::new(),
        Some(msg.to_string()),
        admin,
    ))
}

/// Appends a `credential.changed` event with an `op` metadata field
/// distinguishing MFA enable/disable. Best-effort — failure is logged.
fn audit_mfa_event(
    state: &Arc<WebState>,
    session: &UiSession,
    op: &'static str,
) -> Result<(), crate::audit::AuditError> {
    use crate::audit::{AuditAction, CreateAuditEvent};
    state.audit.append(&CreateAuditEvent {
        tenant_id: session.tenant_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action: AuditAction::CredentialChanged,
        resource_type: "user".to_string(),
        resource_id: session.user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui", "op": op })),
    })?;
    Ok(())
}
