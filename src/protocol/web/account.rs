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

use qrcode::render::svg;
use qrcode::QrCode;

use crate::identity::{CleartextPassword, IdentityError, RegistrationOptions};

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
    tenant_theme_css: Option<String>,
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
            tenant_theme_css: None,
        }
    }
}

/// Renders the `My Account` page for the signed-in user.
pub async fn account_index(State(state): State<Arc<WebState>>, session: UiSession) -> Response {
    let mfa_enabled = state
        .identity
        .mfa_enabled(&session.tenant_id, &session.user_id)
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
    tmpl.tenant_theme_css = state.tenant_theme_css();
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
    tmpl.tenant_theme_css = state.tenant_theme_css();
    render(&tmpl)
}

/// Renders the account index with a flash banner (used on success).
fn render_with_flash(state: &Arc<WebState>, session: &UiSession, flash: Flash) -> Response {
    let mfa_enabled = state
        .identity
        .mfa_enabled(&session.tenant_id, &session.user_id)
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
    tmpl.tenant_theme_css = state.tenant_theme_css();
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
// QR code helper
// ---------------------------------------------------------------------------

/// Renders the given `otpauth://` URI as an inline SVG QR code.
///
/// Returns an empty string on error (the template falls back to showing
/// only the manual secret). This is a presentation concern and belongs
/// in the protocol layer — the identity engine only produces the URI.
fn generate_qr_svg(provisioning_uri: &str) -> String {
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
    tenant_theme_css: Option<String>,
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
            tenant_theme_css: None,
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
        tmpl.tenant_theme_css = state.tenant_theme_css();
        return render(&tmpl);
    }

    let tenant_id = session.tenant_id.clone();
    let user_id = session.user_id.clone();
    let identity = state.identity.clone();
    let enroll_result =
        tokio::task::spawn_blocking(move || identity.enroll_totp(&tenant_id, &user_id)).await;

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
            tmpl.tenant_theme_css = state.tenant_theme_css();
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
            tmpl.tenant_theme_css = state.tenant_theme_css();
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
            tmpl.tenant_theme_css = state.tenant_theme_css();
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

    let tenant_id = session.tenant_id.clone();
    let user_id = session.user_id.clone();
    let code = form.code.trim().to_string();
    let identity = state.identity.clone();
    let verify_result = tokio::task::spawn_blocking(move || {
        identity.verify_totp_enrollment(&tenant_id, &user_id, &code)
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
        tmpl.tenant_theme_css = state.tenant_theme_css();
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
    tmpl.tenant_theme_css = state.tenant_theme_css();
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
        tenant_id: session.tenant_id.clone(),
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
        .list_webauthn_credentials(&session.tenant_id, &session.user_id)
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
        .start_webauthn_registration(&session.tenant_id, &session.user_id, &options)
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
        &session.tenant_id,
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
        &session.tenant_id,
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
