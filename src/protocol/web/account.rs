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
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use qrcode::render::svg;
use qrcode::QrCode;

use crate::core::{SessionId, Timestamp};
use crate::identity::{CleartextPassword, IdentityError, RegistrationOptions};

use super::auth::{clearing_cookies, verify_csrf_form_field, UiSession};
use super::handlers::append_cookie;
use super::handlers_common;
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
    /// Registered `WebAuthn` / passkey credentials for the current user.
    passkey_credentials: Vec<PasskeyRow>,
    // Chrome/layout fields.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

/// A row in the passkey credentials table on the account page.
struct PasskeyRow {
    /// Base64url-encoded credential ID (used in delete form actions).
    id_b64url: String,
    /// Truncated credential ID for display.
    id_short: String,
    /// COSE algorithm identifier (e.g. -7 = ES256).
    algorithm: i64,
    /// Whether this is a discoverable (resident key) credential.
    discoverable: bool,
}

impl AccountIndexTemplate {
    #[allow(clippy::too_many_arguments)]
    fn new(
        session: &UiSession,
        mfa_enabled: bool,
        passkey_credentials: Vec<PasskeyRow>,
        flash: Option<Flash>,
        password_error: Option<String>,
        is_admin: bool,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            password_error,
            mfa_enabled,
            passkey_credentials,
            chrome: true,
            active: "account",
            user_email: Some(session.user_email.clone()),
            is_admin,
            flash,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            realm_theme_css: None,
        }
    }
}

/// Renders the `My Account` page for the signed-in user.
pub async fn account_index(State(state): State<Arc<WebState>>, session: UiSession) -> Response {
    let mfa_enabled = state
        .identity
        .mfa_enabled(&session.realm_id, &session.user_id)
        .unwrap_or(false);
    let passkey_credentials = load_passkey_rows(&state, &session);
    let admin = super::handlers::is_admin(&state, &session);
    let mut tmpl = AccountIndexTemplate::new(
        &session,
        mfa_enabled,
        passkey_credentials,
        None,
        None,
        admin,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css();
    render(&tmpl)
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
        .change_password(&session.realm_id, &session.user_id, &current, &new_pw)
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
        .mfa_enabled(&session.realm_id, &session.user_id)
        .unwrap_or(false);
    let passkey_credentials = load_passkey_rows(state, session);
    let admin = super::handlers::is_admin(state, session);
    let mut tmpl = AccountIndexTemplate::new(
        session,
        mfa_enabled,
        passkey_credentials,
        None,
        Some(msg.to_string()),
        admin,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css();
    render(&tmpl)
}

/// Renders the account index with a flash banner (used on success).
fn render_with_flash(state: &Arc<WebState>, session: &UiSession, flash: Flash) -> Response {
    let mfa_enabled = state
        .identity
        .mfa_enabled(&session.realm_id, &session.user_id)
        .unwrap_or(false);
    let passkey_credentials = load_passkey_rows(state, session);
    let admin = super::handlers::is_admin(state, session);
    let mut tmpl = AccountIndexTemplate::new(
        session,
        mfa_enabled,
        passkey_credentials,
        Some(flash),
        None,
        admin,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css();
    render(&tmpl)
}

/// Appends a `credential.changed` event to the audit log. The event
/// is best-effort — failure is logged and does not fail the response.
fn audit_password_changed(
    state: &Arc<WebState>,
    session: &UiSession,
) -> Result<(), crate::audit::AuditError> {
    use crate::audit::{AuditAction, CreateAuditEvent};
    state.audit.append(&CreateAuditEvent {
        realm_id: session.realm_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action: AuditAction::CredentialChanged,
        resource_type: "user".to_string(),
        resource_id: session.user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui" })),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// QR code helper
// ---------------------------------------------------------------------------

/// Renders the given `otpauth://` URI as an inline SVG QR code.
///
/// Returns an empty string on error (the template falls back to showing
/// only the manual secret). This is a presentation concern and belongs
/// in the protocol layer — the identity engine only produces the URI.
pub fn generate_qr_svg(provisioning_uri: &str) -> String {
    if provisioning_uri.is_empty() {
        return String::new();
    }
    match QrCode::new(provisioning_uri.as_bytes()) {
        Ok(code) => code
            .render()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to generate QR code for TOTP enrolment");
            String::new()
        }
    }
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
    /// Inline SVG of the QR code encoding `provisioning_uri` (empty on error/disabled).
    qr_svg: String,
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
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

impl TotpEnrollTemplate {
    #[allow(clippy::too_many_arguments)]
    fn new(
        session: &UiSession,
        mfa_enabled: bool,
        secret_base32: String,
        provisioning_uri: String,
        qr_svg: String,
        recovery_codes: Vec<String>,
        activation_error: Option<String>,
        is_admin: bool,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            mfa_enabled,
            secret_base32,
            provisioning_uri,
            qr_svg,
            recovery_codes,
            activation_error,
            chrome: true,
            active: "account",
            user_email: Some(session.user_email.clone()),
            is_admin,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            realm_theme_css: None,
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
        .mfa_enabled(&session.realm_id, &session.user_id)
        .unwrap_or(false);

    if enabled {
        let mut tmpl = TotpEnrollTemplate::new(
            &session,
            true,
            String::new(),
            String::new(),
            String::new(),
            Vec::new(),
            None,
            admin,
            state.product_name.clone(),
            state.logo_url.clone(),
        );
        tmpl.theme_css.clone_from(&state.theme_css);
        tmpl.realm_theme_css = state.realm_theme_css();
        return render(&tmpl);
    }

    let realm_id = session.realm_id.clone();
    let user_id = session.user_id.clone();
    let identity = state.identity.clone();
    let enroll_result =
        tokio::task::spawn_blocking(move || identity.enroll_totp(&realm_id, &user_id)).await;

    let enroll_result = match enroll_result {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "enroll_totp spawn_blocking panicked");
            Err(IdentityError::Storage(Box::new(e)))
        }
    };

    match enroll_result {
        Ok(enrollment) => {
            let qr_svg = generate_qr_svg(&enrollment.provisioning_uri);
            let mut tmpl = TotpEnrollTemplate::new(
                &session,
                false,
                enrollment.secret_base32,
                enrollment.provisioning_uri,
                qr_svg,
                enrollment.recovery_codes.as_slice().to_vec(),
                None,
                admin,
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.theme_css.clone_from(&state.theme_css);
            tmpl.realm_theme_css = state.realm_theme_css();
            render(&tmpl)
        }
        Err(IdentityError::MfaAlreadyEnabled) => {
            let mut tmpl = TotpEnrollTemplate::new(
                &session,
                true,
                String::new(),
                String::new(),
                String::new(),
                Vec::new(),
                None,
                admin,
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.theme_css.clone_from(&state.theme_css);
            tmpl.realm_theme_css = state.realm_theme_css();
            render(&tmpl)
        }
        Err(e) => {
            tracing::warn!(error = %e, "enroll_totp failed");
            let mut tmpl = TotpEnrollTemplate::new(
                &session,
                false,
                String::new(),
                String::new(),
                String::new(),
                Vec::new(),
                Some("Unable to start MFA enrolment right now.".to_string()),
                admin,
                state.product_name.clone(),
                state.logo_url.clone(),
            );
            tmpl.theme_css.clone_from(&state.theme_css);
            tmpl.realm_theme_css = state.realm_theme_css();
            render(&tmpl)
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

    let realm_id = session.realm_id.clone();
    let user_id = session.user_id.clone();
    let code = form.code.trim().to_string();
    let identity = state.identity.clone();
    let verify_result = tokio::task::spawn_blocking(move || {
        identity.verify_totp_enrollment(&realm_id, &user_id, &code)
    })
    .await;

    let verify_result = match verify_result {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "verify_totp_enrollment spawn_blocking panicked");
            Err(IdentityError::Storage(Box::new(e)))
        }
    };

    match verify_result {
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
        .disable_mfa(&session.realm_id, &session.user_id)
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

/// `GET /ui/account/totp/recovery-codes.txt`
///
/// Serves the pending plaintext recovery codes as a downloadable text file.
/// Only available during the enrollment window (before the codes are hashed).
/// Returns 404 if MFA is already enabled or no enrollment is pending.
pub async fn totp_download_recovery_codes(
    State(state): State<Arc<WebState>>,
    session: UiSession,
) -> Response {
    use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};

    let mfa_state = match state
        .identity
        .load_pending_recovery_codes(&session.realm_id, &session.user_id)
    {
        Ok(Some(codes)) => codes,
        Ok(None) => return super::handlers_common::not_found("No pending recovery codes"),
        Err(e) => {
            tracing::warn!(error = %e, "load_pending_recovery_codes failed");
            return super::handlers_common::not_found("No pending recovery codes");
        }
    };

    let body = mfa_state.join("\n") + "\n";
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(
            CONTENT_DISPOSITION,
            "attachment; filename=\"hearth-recovery-codes.txt\"",
        )
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| super::handlers_common::not_found("error"))
}

/// `POST /ui/account/totp/regenerate-codes`
///
/// Generates a new set of recovery codes for an already-enrolled user,
/// invalidating any existing codes. Shows the new codes once.
pub async fn totp_regenerate_codes(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    Form(form): Form<DisableTotpForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let realm_id = session.realm_id.clone();
    let user_id = session.user_id.clone();
    let identity = state.identity.clone();
    let result =
        tokio::task::spawn_blocking(move || identity.regenerate_recovery_codes(&realm_id, &user_id))
            .await;

    let codes = match result {
        Ok(Ok(c)) => c,
        Ok(Err(IdentityError::MfaNotEnabled)) => {
            return Redirect::to("/ui/account/totp").into_response();
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "regenerate_recovery_codes failed");
            return render_totp_error(&state, &session, "Unable to regenerate codes right now.");
        }
        Err(e) => {
            tracing::warn!(error = %e, "regenerate_recovery_codes panicked");
            return render_totp_error(&state, &session, "Unable to regenerate codes right now.");
        }
    };

    let admin = super::handlers::is_admin(&state, &session);
    let mut tmpl = TotpEnrollTemplate::new(
        &session,
        false,
        String::new(),
        String::new(),
        String::new(),
        codes,
        None,
        admin,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    // Render in "codes only" mode: mfa_enabled = false shows the enrollment
    // form but we pass empty secret/uri so only the recovery codes section
    // is meaningful. The template's activate form is a no-op here since the
    // user is already enrolled.
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css();
    render(&tmpl)
}

/// Re-renders the TOTP enrolment page with an inline error above the
/// activation form. Used when activation fails without restarting the
/// ceremony.
fn render_totp_error(state: &Arc<WebState>, session: &UiSession, msg: &str) -> Response {
    let admin = super::handlers::is_admin(state, session);
    let enabled = state
        .identity
        .mfa_enabled(&session.realm_id, &session.user_id)
        .unwrap_or(false);

    // When enabled = true the activation form is not shown; in that
    // case there's no meaningful surface for an inline error, so we
    // fall through to rendering the disable form cleanly.
    if enabled {
        let mut tmpl = TotpEnrollTemplate::new(
            session,
            true,
            String::new(),
            String::new(),
            String::new(),
            Vec::new(),
            None,
            admin,
            state.product_name.clone(),
            state.logo_url.clone(),
        );
        tmpl.theme_css.clone_from(&state.theme_css);
        tmpl.realm_theme_css = state.realm_theme_css();
        return render(&tmpl);
    }

    // Render with empty secret/codes because regenerating would
    // invalidate the user's just-scanned QR. They can refresh to
    // restart if they need new recovery codes.
    let mut tmpl = TotpEnrollTemplate::new(
        session,
        false,
        String::new(),
        String::new(),
        String::new(),
        Vec::new(),
        Some(msg.to_string()),
        admin,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css();
    render(&tmpl)
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
        realm_id: session.realm_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action: AuditAction::CredentialChanged,
        resource_type: "user".to_string(),
        resource_id: session.user_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({ "via": "ui", "op": op })),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Passkey / WebAuthn management
// ---------------------------------------------------------------------------

/// Loads the current user's `WebAuthn` credentials as template rows.
fn load_passkey_rows(state: &Arc<WebState>, session: &UiSession) -> Vec<PasskeyRow> {
    state
        .identity
        .list_webauthn_credentials(&session.realm_id, &session.user_id)
        .unwrap_or_default()
        .iter()
        .map(|c| {
            let id_b64url = c.credential_id_b64url();
            let id_short = if id_b64url.len() > 16 {
                format!("{}...", &id_b64url[..16])
            } else {
                id_b64url.clone()
            };
            PasskeyRow {
                id_b64url,
                id_short,
                algorithm: c.algorithm(),
                discoverable: c.discoverable(),
            }
        })
        .collect()
}

/// `GET /ui/account/passkeys/register-begin` — starts a `WebAuthn`
/// registration ceremony and returns the challenge as JSON.
pub async fn passkey_register_begin(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
) -> Response {
    use axum::http::{header, StatusCode};
    use axum::Json;
    use base64::Engine as _;

    // Derive RP ID from Host header (strip port if present).
    let host_str = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let rp_id = host_str
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string();

    let options = RegistrationOptions {
        rp_id: rp_id.clone(),
        discoverable: true,
    };

    match state
        .identity
        .start_webauthn_registration(&session.realm_id, &session.user_id, &options)
    {
        Ok(challenge) => {
            let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge);
            let user_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(session.user_id.as_uuid().as_bytes());
            let body = serde_json::json!({
                "challenge": challenge_b64,
                "rp": { "id": rp_id, "name": state.product_name },
                "user": {
                    "id": user_id_b64,
                    "name": session.user_email,
                    "displayName": session.user_email,
                },
                "pubKeyCredParams": [
                    { "type": "public-key", "alg": -7 },   // ES256
                    { "type": "public-key", "alg": -257 }, // RS256
                ],
                "authenticatorSelection": {
                    "residentKey": "preferred",
                    "userVerification": "preferred",
                },
                "attestation": "none",
            });
            Json(body).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "start_webauthn_registration failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Registration unavailable",
            )
                .into_response()
        }
    }
}

/// JSON body from the browser `WebAuthn` registration completion.
#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterCompleteBody {
    /// Base64url-encoded `clientDataJSON` from the authenticator.
    pub client_data_json: String,
    /// Base64url-encoded `attestationObject` from the authenticator.
    pub attestation_object: String,
}

/// `POST /ui/account/passkeys/register-complete` — completes the
/// `WebAuthn` registration ceremony and stores the credential.
pub async fn passkey_register_complete(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<PasskeyRegisterCompleteBody>,
) -> Response {
    use axum::http::{header, StatusCode};
    use base64::Engine as _;

    let Ok(client_data_json) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&body.client_data_json)
    else {
        return (StatusCode::BAD_REQUEST, "Invalid client_data_json").into_response();
    };
    let Ok(attestation_object) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&body.attestation_object)
    else {
        return (StatusCode::BAD_REQUEST, "Invalid attestation_object").into_response();
    };

    // Derive origin from Host header.
    let host_str = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = if host_str.starts_with("localhost") || host_str.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    };
    let origin = format!("{scheme}://{host_str}");

    match state.identity.complete_webauthn_registration(
        &session.realm_id,
        &session.user_id,
        &client_data_json,
        &attestation_object,
        &origin,
        true, // discoverable
    ) {
        Ok(_cred) => {
            if let Err(e) = audit_mfa_event(&state, &session, "passkey_register") {
                tracing::warn!(error = %e, "passkey register audit append failed");
            }
            (StatusCode::OK, "OK").into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "complete_webauthn_registration failed");
            (StatusCode::BAD_REQUEST, "Registration failed").into_response()
        }
    }
}

/// `application/x-www-form-urlencoded` body for passkey deletion.
#[derive(Debug, Deserialize)]
pub struct DeletePasskeyForm {
    /// CSRF double-submit token.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/account/passkeys/:cred_id/delete` — revokes the user's
/// own passkey credential.
pub async fn passkey_delete(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    axum::extract::Path(cred_id_b64): axum::extract::Path<String>,
    Form(form): Form<DeletePasskeyForm>,
) -> Response {
    use base64::Engine as _;

    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let Ok(cred_id_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&cred_id_b64)
    else {
        return Redirect::to("/ui/account").into_response();
    };

    match state.identity.revoke_webauthn_credential(
        &session.realm_id,
        &session.user_id,
        &cred_id_bytes,
    ) {
        Ok(()) => {
            if let Err(e) = audit_mfa_event(&state, &session, "passkey_revoke") {
                tracing::warn!(error = %e, "passkey revoke audit append failed");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "revoke_webauthn_credential failed");
        }
    }

    Redirect::to("/ui/account").into_response()
}

// ---------------------------------------------------------------------------
// Self-service session management
// ---------------------------------------------------------------------------

/// A single row rendered on the "My Sessions" page.
struct AccountSessionRow {
    /// UUID (string form) — used in form action URLs.
    id: String,
    /// Best-effort device descriptor (browser + OS, e.g., "Chrome, macOS").
    device_label: String,
    /// Client IP (or em-dash if unknown).
    ip_address: String,
    /// Human-readable creation timestamp.
    created_at: String,
    /// Human-readable last-refreshed timestamp (same as created on fresh sessions).
    last_active: String,
    /// Human-readable expiration timestamp.
    expires_at: String,
    /// `true` iff this row matches the session that made the current request.
    is_current: bool,
}

/// Template rendered by `GET /ui/account/sessions`.
#[derive(Template)]
#[template(path = "ui/account/sessions.html")]
#[allow(clippy::struct_excessive_bools)]
struct AccountSessionsTemplate {
    sessions: Vec<AccountSessionRow>,
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    flash: Option<Flash>,
    csrf: Option<String>,
    narrow: bool,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

impl AccountSessionsTemplate {
    fn new(
        session: &UiSession,
        sessions: Vec<AccountSessionRow>,
        is_admin: bool,
        product_name: String,
        logo_url: String,
    ) -> Self {
        Self {
            sessions,
            chrome: true,
            active: "account",
            user_email: Some(session.user_email.clone()),
            is_admin,
            flash: None,
            csrf: session.csrf.clone(),
            narrow: true,
            product_name,
            logo_url,
            theme_css: String::new(),
            realm_theme_css: None,
        }
    }
}

/// `GET /ui/account/sessions` — lists the signed-in user's active sessions.
pub async fn sessions_index(State(state): State<Arc<WebState>>, session: UiSession) -> Response {
    let rows = load_session_rows(&state, &session);
    let admin = super::handlers::is_admin(&state, &session);
    let mut tmpl = AccountSessionsTemplate::new(
        &session,
        rows,
        admin,
        state.product_name.clone(),
        state.logo_url.clone(),
    );
    tmpl.theme_css.clone_from(&state.theme_css);
    tmpl.realm_theme_css = state.realm_theme_css();
    render(&tmpl)
}

/// CSRF-only form body for session revocation endpoints.
#[derive(Debug, Deserialize)]
pub struct RevokeSessionForm {
    /// CSRF double-submit token.
    #[serde(rename = "_csrf", default)]
    pub csrf: String,
}

/// `POST /ui/account/sessions/{sid}/revoke` — revokes a single session
/// belonging to the signed-in user.
///
/// The target session id is parsed from the path and must belong to the
/// authenticated user — otherwise the handler returns 404 to avoid
/// leaking session-id existence across users. Revoking the *current*
/// session clears both UI cookies and redirects to `/ui/login`.
pub async fn revoke_session(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    axum::extract::Path(sid): axum::extract::Path<String>,
    Form(form): Form<RevokeSessionForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let Ok(uuid) = sid.parse::<uuid::Uuid>() else {
        return handlers_common::not_found("Session not found");
    };
    let target = SessionId::new(uuid);

    // Ownership check: fetch the target and confirm it belongs to the
    // authenticated user. Returning 404 (rather than 403) hides whether
    // a given session id even exists in the realm.
    let target_session = match state.identity.get_session(&session.realm_id, &target) {
        Ok(Some(s)) if s.user_id() == &session.user_id => s,
        Ok(_) => return handlers_common::not_found("Session not found"),
        Err(e) => {
            tracing::warn!(error = %e, "sessions: get_session failed");
            return handlers_common::server_error();
        }
    };

    let is_current = target_session.id() == &session.session_id;

    match state.identity.revoke_session(&session.realm_id, &target) {
        Ok(()) | Err(IdentityError::SessionNotFound) => {
            audit_self_session_revoke(&state, &session, &target, false);
        }
        Err(e) => {
            tracing::warn!(error = %e, "revoke_session failed");
            return handlers_common::server_error();
        }
    }

    if is_current {
        let mut response = Redirect::to("/ui/login").into_response();
        for cookie in clearing_cookies() {
            append_cookie(&mut response, &cookie);
        }
        response
    } else {
        Redirect::to("/ui/account/sessions").into_response()
    }
}

/// `POST /ui/account/sessions/revoke-others` — revokes every session
/// belonging to the signed-in user *except* the one that made this
/// request. Pages through `list_sessions_by_user` to cover users with
/// more sessions than fit in a single page.
pub async fn revoke_other_sessions(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    Form(form): Form<RevokeSessionForm>,
) -> Response {
    if let Err(resp) = verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    let mut cursor: Option<String> = None;
    loop {
        let page = match state.identity.list_sessions_by_user(
            &session.realm_id,
            &session.user_id,
            cursor.as_deref(),
            100,
        ) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "revoke_other: list_sessions_by_user failed");
                return handlers_common::server_error();
            }
        };
        for s in &page.items {
            if s.id() == &session.session_id || s.is_revoked() {
                continue;
            }
            let sid = s.id().clone();
            match state.identity.revoke_session(&session.realm_id, &sid) {
                Ok(()) | Err(IdentityError::SessionNotFound) => {
                    audit_self_session_revoke(&state, &session, &sid, true);
                }
                Err(e) => {
                    tracing::warn!(error = %e, session_id = %sid.as_uuid(), "revoke_session failed in batch");
                }
            }
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    Redirect::to("/ui/account/sessions").into_response()
}

/// Appends a `SessionRevoked` audit event for a self-service revocation.
///
/// The `metadata.via` field is set to `"self"` so operators can
/// distinguish user-initiated revocations from admin-initiated ones
/// (which emit `metadata.via == "ui"`).
fn audit_self_session_revoke(
    state: &Arc<WebState>,
    session: &UiSession,
    target: &SessionId,
    batch: bool,
) {
    use crate::audit::{AuditAction, CreateAuditEvent};
    let metadata = if batch {
        serde_json::json!({ "via": "self", "batch": true })
    } else {
        serde_json::json!({ "via": "self" })
    };
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: session.realm_id.clone(),
        actor: session.user_id.as_uuid().to_string(),
        action: AuditAction::SessionRevoked,
        resource_type: "session".to_string(),
        resource_id: target.as_uuid().to_string(),
        metadata: Some(metadata),
    }) {
        tracing::warn!(error = %e, "self session revoke audit append failed");
    }
}

/// Loads the signed-in user's active sessions into template rows,
/// flagging the row whose id matches the current request's session.
fn load_session_rows(state: &Arc<WebState>, session: &UiSession) -> Vec<AccountSessionRow> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = match state.identity.list_sessions_by_user(
            &session.realm_id,
            &session.user_id,
            cursor.as_deref(),
            50,
        ) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "list_sessions_by_user failed");
                break;
            }
        };
        for s in page.items {
            if s.is_revoked() {
                continue;
            }
            out.push(AccountSessionRow {
                id: s.id().as_uuid().to_string(),
                device_label: s
                    .device_label()
                    .map_or_else(|| "Unknown device".to_string(), str::to_string),
                ip_address: s
                    .ip_address()
                    .map_or_else(|| "—".to_string(), str::to_string),
                created_at: format_ts(s.created_at()),
                last_active: format_ts(s.last_refreshed_at()),
                expires_at: format_ts(s.expires_at()),
                is_current: s.id() == &session.session_id,
            });
        }
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    out
}

/// Formats a `Timestamp` (Unix micros) as `YYYY-MM-DD HH:MM UTC`.
fn format_ts(ts: Timestamp) -> String {
    let secs = ts.as_micros() / 1_000_000;
    let rem = secs.rem_euclid(86_400);
    let days = secs.div_euclid(86_400);
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
}

/// Converts days since the Unix epoch into `(year, month, day)` using
/// Howard Hinnant's `civil_from_days` algorithm (proleptic Gregorian).
#[allow(clippy::similar_names)] // `doe`/`doy` are the canonical names in Hinnant's algorithm
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
