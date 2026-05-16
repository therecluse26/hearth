//! Browser-facing OAuth authorization endpoint + consent interstitial.
//!
//! RFC 6749 §4.1 requires a browser-redirect `GET /authorize` endpoint
//! where the user interactively approves the authorization request. The
//! existing JSON `POST /authorize` at `src/protocol/http.rs` is for
//! machine clients and SDKs and bypasses consent.
//!
//! This module adds:
//!
//! | Route | Method | Purpose |
//! |-------|--------|---------|
//! | `/ui/oauth/authorize` | GET | RFC 6749 redirect entry point |
//! | `/ui/realms/{realm}/oauth/authorize` | GET | Realm-scoped variant |
//! | `/ui/oauth/consent` | GET | Render consent prompt |
//! | `/ui/oauth/consent` | POST | Approve / deny submit |
//!
//! Flow:
//!
//! 1. `GET /ui/oauth/authorize` — validate query params against registered
//!    `OAuthClient`, require a valid `UiSession`, check existing
//!    [`ConsentRecord`]. If the record covers every requested scope
//!    (or `require_consent=false`), skip straight to code issuance and
//!    302 back to `redirect_uri`. Otherwise stash a
//!    [`PendingAuthorizationRequest`] under an opaque ticket and
//!    redirect to the consent page.
//! 2. `GET /ui/oauth/consent` — render the interstitial showing client
//!    name, logo (if set), and per-scope checkboxes.
//! 3. `POST /ui/oauth/consent` — validate CSRF + ticket, either:
//!    - `decision=approve` → verify approved scopes are a subset of the
//!      originally requested set, persist consent, emit
//!      [`AuditAction::ConsentGranted`], issue code, 302 to redirect URI.
//!    - `decision=deny` → emit [`AuditAction::ConsentDenied`], 302 to
//!      `redirect_uri?error=access_denied&state=...` per RFC 6749 §4.1.2.1.
//!
//! # Security notes
//!
//! * Ticket cookie is HMAC-signed with [`CookieSecret`] and bound to the
//!   current `UiSession`'s `user_id` so cross-user replay is detectable.
//! * The engine's pending-auth record independently re-checks the `user_id`
//!   before issuing a code — cookie compromise alone is not sufficient.
//! * POST-submitted `approved_scopes` must be a subset of the original
//!   request's scope list. Tampering returns
//!   [`IdentityError::ConsentScopeNotRequested`].
//! * `prompt=none` with no sufficient existing consent returns
//!   `error=consent_required` per OIDC Core §3.1.2.1.
//! * `prompt=consent` forces re-prompting even if a matching consent
//!   record exists — per OIDC Core §3.1.2.1.

use std::collections::BTreeSet;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::core::{ClientId, RealmId, Timestamp, UserId};
use crate::identity::{
    canonicalize_scopes, CodeChallengeMethod, IdentityError, PendingAuthorizationRequest,
};

use super::auth::{CookieSecret, UiSession};
use super::handlers::append_cookie;
use super::handlers_common;
use super::templates::render;
use super::WebState;

/// Ticket cookie name. Short-lived, signed, bound to the `UiSession` user id.
pub const CONSENT_TICKET_COOKIE: &str = "hearth_ui_oauth_ticket";

/// TTL for a pending-authorization ticket in seconds (10 minutes — same
/// ballpark as the OAuth authorization code TTL).
pub const CONSENT_TICKET_TTL_SECS: i64 = 600;

// ---------------------------------------------------------------------------
// Query parameters (RFC 6749 §4.1.1 + OIDC Core §3.1.2.1)
// ---------------------------------------------------------------------------

/// Query parameters accepted by `GET /ui/oauth/authorize`.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    /// OAuth client id (UUID string).
    #[serde(default)]
    pub client_id: String,
    /// Registered redirect URI the user agent is returned to.
    #[serde(default)]
    pub redirect_uri: String,
    /// Must be `"code"` — implicit and hybrid flows are not supported.
    #[serde(default)]
    pub response_type: String,
    /// Space-delimited scope string. May be empty.
    #[serde(default)]
    pub scope: String,
    /// CSRF-protecting opaque value echoed back to the client.
    #[serde(default)]
    pub state: String,
    /// PKCE challenge.
    #[serde(default)]
    pub code_challenge: String,
    /// PKCE challenge method. Only `S256` is accepted.
    #[serde(default)]
    pub code_challenge_method: String,
    /// OIDC nonce — echoed into the ID token.
    #[serde(default)]
    pub nonce: String,
    /// OIDC `prompt` parameter. Supported: `none`, `consent`, or empty.
    #[serde(default)]
    pub prompt: String,
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

/// A single scope row on the consent prompt.
struct ConsentScopeRow {
    /// Raw scope value (e.g. `"profile"`).
    name: String,
    /// Whether the user has already granted this scope previously.
    /// Pre-checked in the UI for convenience but explicitly re-submitted.
    already_granted: bool,
}

/// Template rendered by `GET /ui/oauth/consent`.
#[derive(Template)]
#[template(path = "ui/oauth/consent.html")]
struct ConsentTemplate {
    /// Client display name for the "{app} wants to access..." header.
    client_name: String,
    /// Optional client logo URL. `None` renders a generic icon.
    client_logo_url: Option<String>,
    /// Requested scopes + pre-granted state.
    scopes: Vec<ConsentScopeRow>,
    /// Opaque ticket — submitted back with the decision.
    ticket: String,
    /// CSRF double-submit token (`hearth_ui_csrf` cookie value).
    csrf: Option<String>,
    // Layout chrome.
    chrome: bool,
    active: &'static str,
    user_email: Option<String>,
    is_admin: bool,
    narrow: bool,
    flash: Option<super::templates::Flash>,
    product_name: String,
    logo_url: String,
    theme_css: String,
    realm_theme_css: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point: GET /ui/oauth/authorize
// ---------------------------------------------------------------------------

/// Bare `GET /ui/oauth/authorize` — uses the current UI session's realm.
pub async fn authorize_get(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let realm = session.realm_id.clone();
    authorize_get_impl(&state, &session, &realm, &q).await
}

/// Realm-scoped variant at `GET /ui/realms/{realm}/oauth/authorize`.
///
/// The path-scoped realm MUST match the signed-in session's realm; a
/// mismatch returns 404 (not a bypass surface).
pub async fn authorize_get_scoped(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let Ok(Some(realm)) = state.identity.get_realm_by_name(&realm_name) else {
        return handlers_common::not_found("Realm not found");
    };
    if realm.id() != &session.realm_id {
        return handlers_common::not_found("Realm not found");
    }
    authorize_get_impl(&state, &session, realm.id(), &q).await
}

#[allow(clippy::unused_async, clippy::too_many_lines)]
async fn authorize_get_impl(
    state: &Arc<WebState>,
    session: &UiSession,
    realm: &RealmId,
    q: &AuthorizeQuery,
) -> Response {
    // 1. Basic parameter validation before we reveal anything about the client.
    if q.response_type != "code" {
        return handlers_common::bad_request("response_type must be 'code'");
    }
    if q.state.is_empty() {
        return handlers_common::bad_request("state parameter is required for CSRF protection");
    }
    let Ok(client_uuid) = uuid::Uuid::parse_str(&q.client_id) else {
        return handlers_common::bad_request("invalid client_id");
    };
    let client_id = ClientId::new(client_uuid);

    // 2. Load the client and validate redirect_uri BEFORE any error
    //    redirect — per RFC 6749 §4.1.2.1, we must only redirect errors
    //    back to a confirmed-registered URI.
    let client = match state.identity.get_client(realm, &client_id) {
        Ok(Some(c)) => c,
        Ok(None) => return handlers_common::bad_request("unknown client"),
        Err(e) => {
            tracing::warn!(error = %e, "authorize_get: get_client failed");
            return handlers_common::server_error();
        }
    };
    if !client.redirect_uris().iter().any(|u| u == &q.redirect_uri) {
        return handlers_common::bad_request("invalid redirect_uri");
    }

    // 3. PKCE method sanity check.
    let code_challenge_method = match q.code_challenge_method.as_str() {
        "" => None,
        "S256" => Some(CodeChallengeMethod::S256),
        _ => {
            return redirect_with_oauth_error(
                &q.redirect_uri,
                "invalid_request",
                "unsupported code_challenge_method",
                &q.state,
            );
        }
    };

    // 3b. Public clients MUST supply PKCE S256 (RFC 9700 / HEA-501 F-01).
    if !client.is_confidential() && q.code_challenge.is_empty() {
        return redirect_with_oauth_error(
            &q.redirect_uri,
            "invalid_request",
            "public clients must use PKCE with code_challenge_method=S256",
            &q.state,
        );
    }

    // 4. Canonicalize requested scopes once for consent matching.
    let requested_scopes = canonicalize_scopes(
        q.scope
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>(),
    );

    // 5. Existing consent lookup.
    let existing = match state
        .identity
        .get_consent(realm, &session.user_id, &client_id)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "authorize_get: get_consent failed");
            return handlers_common::server_error();
        }
    };
    let covered = existing
        .as_ref()
        .is_some_and(|r| r.covers(&requested_scopes));

    // 6. OIDC prompt handling.
    let force_prompt = q.prompt == "consent";
    let silent_only = q.prompt == "none";

    let bypass = !client.require_consent() || (covered && !force_prompt);

    if bypass {
        return issue_code_and_redirect(
            state,
            realm,
            &session.user_id,
            &client_id,
            &q.redirect_uri,
            &requested_scopes.join(" "),
            &q.state,
            optional(&q.code_challenge),
            code_challenge_method,
            optional(&q.nonce),
        );
    }

    if silent_only {
        // OIDC Core §3.1.2.1: when `prompt=none` and consent is needed,
        // respond with `error=consent_required` on the redirect URI.
        return redirect_with_oauth_error(
            &q.redirect_uri,
            "consent_required",
            "user consent required",
            &q.state,
        );
    }

    // 7. Store pending-auth + redirect to consent page.
    let now = Timestamp::from_micros(now_micros());
    let pending = PendingAuthorizationRequest {
        user_id: session.user_id.clone(),
        client_id: client_id.clone(),
        redirect_uri: q.redirect_uri.clone(),
        requested_scopes,
        state: q.state.clone(),
        response_type: q.response_type.clone(),
        code_challenge: optional(&q.code_challenge),
        code_challenge_method: code_challenge_method.as_ref().map(|_| "S256".to_string()),
        nonce: optional(&q.nonce),
        created_at: now,
        expires_at: now.add_micros(CONSENT_TICKET_TTL_SECS * 1_000_000),
    };
    let ticket = match state.identity.put_pending_authorization(realm, &pending) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "put_pending_authorization failed");
            return handlers_common::server_error();
        }
    };
    let cookie = issue_ticket_cookie(&state.cookie_secret, &session.user_id, &ticket);
    let mut response = Redirect::to("/ui/oauth/consent").into_response();
    append_cookie(&mut response, &cookie);
    response
}

// ---------------------------------------------------------------------------
// GET /ui/oauth/consent
// ---------------------------------------------------------------------------

/// Renders the consent interstitial for a pending authorization request.
pub async fn consent_page(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(ticket_value) = read_ticket_cookie(&headers) else {
        return handlers_common::bad_request("no pending authorization");
    };
    let Some(ticket) =
        validate_ticket_cookie(&state.cookie_secret, &session.user_id, &ticket_value)
    else {
        return handlers_common::bad_request("consent ticket invalid");
    };

    // Peek the pending request without consuming the ticket — we do a
    // real take on the POST path. This peek uses get_consent of a sibling
    // nature: we need to scan the ticket-keyed entry. Since
    // `take_pending_authorization` consumes, we instead fetch via a
    // lightweight path: re-issuing would require a lookup-only engine
    // method. For simplicity we read via `get_pending_authorization`
    // helper added below.
    let pending = match peek_pending(&state, &session.realm_id, &ticket) {
        Ok(p) => p,
        Err(PeekErr::NotFound | PeekErr::Expired) => {
            return handlers_common::bad_request("consent ticket invalid")
        }
        Err(PeekErr::Storage) => return handlers_common::server_error(),
    };

    // Cross-user guard: the pending record embeds the user_id. Tampered
    // cookies that happen to MAC-validate still don't grant consent for
    // another user.
    if pending.user_id != session.user_id {
        return handlers_common::bad_request("consent ticket invalid");
    }

    // Load the client for display fields + determine pre-granted scopes.
    let client = match state
        .identity
        .get_client(&session.realm_id, &pending.client_id)
    {
        Ok(Some(c)) => c,
        Ok(None) => return handlers_common::bad_request("unknown client"),
        Err(_) => return handlers_common::server_error(),
    };
    let existing = state
        .identity
        .get_consent(&session.realm_id, &session.user_id, &pending.client_id)
        .ok()
        .flatten();

    let scopes: Vec<ConsentScopeRow> = pending
        .requested_scopes
        .iter()
        .map(|s| ConsentScopeRow {
            name: s.clone(),
            already_granted: existing
                .as_ref()
                .is_some_and(|r| r.granted_scopes.iter().any(|g| g == s)),
        })
        .collect();

    let admin = super::handlers::is_admin(state.as_ref(), &session);
    let mut tmpl = ConsentTemplate {
        client_name: client.client_name().to_string(),
        client_logo_url: client.client_logo_url().map(str::to_string),
        scopes,
        ticket,
        csrf: session.csrf.clone(),
        chrome: true,
        active: "account",
        user_email: Some(session.user_email.clone()),
        is_admin: admin,
        narrow: true,
        flash: None,
        product_name: state.product_name.clone(),
        logo_url: state.logo_url.clone(),
        theme_css: state.theme_css.clone(),
        realm_theme_css: state.realm_theme_css(),
    };
    tmpl.theme_css.clone_from(&state.theme_css);
    render(&tmpl)
}

// ---------------------------------------------------------------------------
// POST /ui/oauth/consent
// ---------------------------------------------------------------------------

/// Parsed consent-submit form. Built via [`parse_consent_form`] from the
/// raw body because `serde_urlencoded` (axum's default) does not collect
/// repeated `scope=` fields into a `Vec<String>`.
struct ConsentSubmitForm {
    /// Opaque ticket (single-use).
    pub ticket: String,
    /// `"approve"` or `"deny"`.
    pub decision: String,
    /// Scopes the user approved (repeated `scope=` fields).
    pub scopes: Vec<String>,
    /// CSRF double-submit token.
    pub csrf: String,
}

/// Parses an `application/x-www-form-urlencoded` body into a
/// [`ConsentSubmitForm`], collecting repeated `scope=` keys into a
/// `Vec<String>`.
fn parse_consent_form(body: &[u8]) -> ConsentSubmitForm {
    let mut ticket = String::new();
    let mut decision = String::new();
    let mut scopes: Vec<String> = Vec::new();
    let mut csrf = String::new();
    for (k, v) in form_urlencoded::parse(body) {
        match k.as_ref() {
            "ticket" => ticket = v.into_owned(),
            "decision" => decision = v.into_owned(),
            "scope" => scopes.push(v.into_owned()),
            "_csrf" => csrf = v.into_owned(),
            _ => {}
        }
    }
    ConsentSubmitForm {
        ticket,
        decision,
        scopes,
        csrf,
    }
}

/// Handles `POST /ui/oauth/consent`.
#[allow(clippy::too_many_lines)]
pub async fn consent_submit(
    State(state): State<Arc<WebState>>,
    session: UiSession,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let form = parse_consent_form(&body);
    if let Err(resp) = super::auth::verify_csrf_form_field(&session, &form.csrf) {
        return resp;
    }

    // Validate ticket cookie matches the form-posted ticket and is
    // MAC-bound to the current user.
    let Some(cookie_value) = read_ticket_cookie(&headers) else {
        return handlers_common::bad_request("consent ticket invalid");
    };
    let Some(ticket_from_cookie) =
        validate_ticket_cookie(&state.cookie_secret, &session.user_id, &cookie_value)
    else {
        return handlers_common::bad_request("consent ticket invalid");
    };
    if ticket_from_cookie != form.ticket {
        return handlers_common::bad_request("consent ticket invalid");
    }

    // Consume the ticket — single-use, regardless of decision.
    let pending = match state
        .identity
        .take_pending_authorization(&session.realm_id, &form.ticket)
    {
        Ok(p) => p,
        Err(IdentityError::ConsentTicketNotFound | IdentityError::ConsentTicketExpired) => {
            return handlers_common::bad_request("consent ticket invalid");
        }
        Err(e) => {
            tracing::warn!(error = %e, "take_pending_authorization failed");
            return handlers_common::server_error();
        }
    };

    // Ownership guard redundant with the cookie MAC check, but cheap.
    if pending.user_id != session.user_id {
        return handlers_common::bad_request("consent ticket invalid");
    }

    // Clear the ticket cookie regardless of outcome.
    let clear_cookie =
        format!("{CONSENT_TICKET_COOKIE}=; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=0");

    #[allow(clippy::single_match_else, clippy::match_same_arms)]
    match form.decision.as_str() {
        "approve" => {
            // Validate approved scopes are a subset of requested.
            let requested: BTreeSet<&String> = pending.requested_scopes.iter().collect();
            let approved = canonicalize_scopes(form.scopes.clone());
            for s in &approved {
                if !requested.contains(&s) {
                    return handlers_common::bad_request("scope not in original request");
                }
            }

            // Persist consent (even if approved is empty — the user
            // chose "approve no scopes", which still satisfies the
            // request for an authorization code).
            if let Err(e) = state.identity.grant_consent(
                &session.realm_id,
                &session.user_id,
                &pending.client_id,
                &approved,
            ) {
                tracing::warn!(error = %e, "grant_consent failed");
                return handlers_common::server_error();
            }
            // Engine now emits ConsentGranted internally; metadata-threading
            // for via/scopes context tracked in follow-up.

            let method = pending.code_challenge_method.as_deref().and_then(|m| {
                if m == "S256" {
                    Some(CodeChallengeMethod::S256)
                } else {
                    None
                }
            });
            let mut response = issue_code_and_redirect(
                &state,
                &session.realm_id,
                &session.user_id,
                &pending.client_id,
                &pending.redirect_uri,
                &approved.join(" "),
                &pending.state,
                pending.code_challenge.clone(),
                method,
                pending.nonce.clone(),
            );
            append_cookie(&mut response, &clear_cookie);
            response
        }
        _ => {
            audit_consent_event(
                &state,
                &session.realm_id,
                &session.user_id,
                &pending.client_id,
                AuditAction::ConsentDenied,
                &pending.requested_scopes,
                "self",
            );
            let mut response = redirect_with_oauth_error(
                &pending.redirect_uri,
                "access_denied",
                "user denied authorization",
                &pending.state,
            );
            append_cookie(&mut response, &clear_cookie);
            response
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn optional(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Wall-clock "now" in Unix microseconds. `Timestamp` uses the engine
/// `Clock`; for pending-auth TTLs we just need a coarse wall value since
/// the engine itself re-checks expiry at take-time using its own clock.
fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// Builds a signed ticket cookie value: `{ticket}.{mac}` where the MAC
/// covers `user_id|ticket` with [`CookieSecret`]. Binding to the user id
/// makes cross-user replay detectable even if the cookie is copied.
fn issue_ticket_cookie(secret: &CookieSecret, user_id: &UserId, ticket: &str) -> String {
    let mac = compute_ticket_mac(secret, user_id, ticket);
    let value = format!("{ticket}.{mac}");
    format!(
        "{CONSENT_TICKET_COOKIE}={value}; HttpOnly; Path=/ui; SameSite=Lax; Max-Age={CONSENT_TICKET_TTL_SECS}"
    )
}

fn compute_ticket_mac(secret: &CookieSecret, user_id: &UserId, ticket: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret_as_bytes(secret))
        .expect("HMAC-SHA256 accepts any 32-byte key");
    mac.update(user_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(ticket.as_bytes());
    BASE64URL_NOPAD.encode(&mac.finalize().into_bytes())
}

/// Exposes the `[u8; 32]` inside [`CookieSecret`] without adding a public
/// accessor. This is a read-only borrow — if the representation of
/// `CookieSecret` changes, update this one place.
fn secret_as_bytes(secret: &CookieSecret) -> &[u8] {
    // Use a tiny hack to borrow via the Debug path: `CookieSecret` is
    // `Arc<[u8; 32]>`. We `clone()` to bump the Arc refcount, then keep
    // the Arc alive by returning a static-lifetime reference derived
    // from a `Box::leak` pattern is overkill. Instead we serialize via
    // the public signing path: re-implement inline.
    //
    // NB: the auth module owns `CookieSecret::as_bytes` (pub(super)).
    // Here we re-use the same trick via the `Mac::new_from_slice` →
    // `compute_mac` path already present. Simpler: call through a
    // helper defined in `auth`.
    //
    // Pragmatic path: we expose `CookieSecret::as_bytes_public` via a
    // newtype shim in `auth.rs` so this module can read it.
    // Implemented below via a re-export — see `super::auth::cookie_secret_bytes`.
    super::auth::cookie_secret_bytes(secret)
}

/// Reads the raw ticket cookie value from request headers. Returns
/// `None` when absent.
fn read_ticket_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    super::auth::cookie_value_from_headers(headers, CONSENT_TICKET_COOKIE).map(str::to_string)
}

/// Parses and MAC-validates a ticket cookie value. Returns the inner
/// ticket on success.
fn validate_ticket_cookie(secret: &CookieSecret, user_id: &UserId, value: &str) -> Option<String> {
    let (ticket, mac_str) = value.rsplit_once('.')?;
    let expected = compute_ticket_mac(secret, user_id, ticket);
    let ok: bool = expected.as_bytes().ct_eq(mac_str.as_bytes()).into();
    if ok {
        Some(ticket.to_string())
    } else {
        None
    }
}

/// Lightweight non-consuming peek at a pending authorization ticket.
///
/// The engine's [`take_pending_authorization`] is single-use. For the
/// consent page render we want to read without consuming. We do that by
/// issuing a direct storage read through the engine's
/// `get_pending_authorization` extension defined below.
enum PeekErr {
    NotFound,
    Expired,
    Storage,
}

fn peek_pending(
    state: &Arc<WebState>,
    realm: &RealmId,
    ticket: &str,
) -> Result<PendingAuthorizationRequest, PeekErr> {
    state
        .identity
        .get_pending_authorization(realm, ticket)
        .map_err(|e| match e {
            IdentityError::ConsentTicketNotFound => PeekErr::NotFound,
            IdentityError::ConsentTicketExpired => PeekErr::Expired,
            _ => PeekErr::Storage,
        })
        .and_then(|opt| opt.ok_or(PeekErr::NotFound))
}

/// Issues an authorization code by calling into the engine and redirects
/// the user-agent to `redirect_uri?code=...&state=...`.
#[allow(clippy::too_many_arguments)]
fn issue_code_and_redirect(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    client_id: &ClientId,
    redirect_uri: &str,
    scope: &str,
    state_param: &str,
    code_challenge: Option<String>,
    code_challenge_method: Option<CodeChallengeMethod>,
    nonce: Option<String>,
) -> Response {
    match state.identity.issue_authorization_code(
        realm,
        user_id,
        client_id,
        redirect_uri,
        scope,
        state_param,
        code_challenge,
        code_challenge_method,
        nonce,
    ) {
        Ok(resp) => {
            // RFC 9207: include iss= in authorization response to prevent mix-up attacks
            let location = append_query(
                redirect_uri,
                &[
                    ("code", resp.code()),
                    ("state", resp.state()),
                    ("iss", resp.iss()),
                ],
            );
            Redirect::to(&location).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "issue_authorization_code failed");
            handlers_common::server_error()
        }
    }
}

/// Builds a redirect URI with OAuth error parameters (RFC 6749 §4.1.2.1).
fn redirect_with_oauth_error(
    redirect_uri: &str,
    error: &str,
    description: &str,
    state: &str,
) -> Response {
    let location = append_query(
        redirect_uri,
        &[
            ("error", error),
            ("error_description", description),
            ("state", state),
        ],
    );
    Redirect::to(&location).into_response()
}

/// Appends query parameters to a URI, choosing `?` vs `&` based on
/// whether the base already has a query string.
fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(base.len() + 64);
    out.push_str(base);
    let mut first = !base.contains('?');
    for (k, v) in params {
        if v.is_empty() {
            continue;
        }
        out.push(if first { '?' } else { '&' });
        first = false;
        percent_encode_into(k, &mut out);
        out.push('=');
        percent_encode_into(v, &mut out);
    }
    out
}

/// Minimal percent-encoder for OAuth redirect parameters.
fn percent_encode_into(value: &str, out: &mut String) {
    use std::fmt::Write as _;
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
}

/// Appends a single consent audit event. Best-effort.
fn audit_consent_event(
    state: &Arc<WebState>,
    realm: &RealmId,
    user_id: &UserId,
    client_id: &ClientId,
    action: AuditAction,
    scopes: &[String],
    via: &'static str,
) {
    if let Err(e) = state.audit.append(&CreateAuditEvent {
        realm_id: realm.clone(),
        actor: user_id.as_uuid().to_string(),
        action,
        resource_type: "oauth_client".to_string(),
        resource_id: client_id.as_uuid().to_string(),
        metadata: Some(serde_json::json!({
            "via": via,
            "scopes": scopes,
            "client_id": client_id.as_uuid().to_string(),
        })),
    }) {
        tracing::warn!(error = %e, "consent audit append failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_cookie_detects_user_substitution() {
        let secret = CookieSecret::from_bytes([1u8; 32]);
        let u1 = UserId::generate();
        let u2 = UserId::generate();
        let ticket = "abc-123";
        let cookie_full = issue_ticket_cookie(&secret, &u1, ticket);
        // Extract raw value (strip the "name=" prefix and attributes).
        let raw = cookie_full
            .strip_prefix(&format!("{CONSENT_TICKET_COOKIE}="))
            .expect("prefix")
            .split(';')
            .next()
            .expect("value");
        assert_eq!(
            validate_ticket_cookie(&secret, &u1, raw).as_deref(),
            Some(ticket)
        );
        assert!(validate_ticket_cookie(&secret, &u2, raw).is_none());
    }

    #[test]
    fn ticket_cookie_detects_malformed() {
        let secret = CookieSecret::from_bytes([2u8; 32]);
        let u = UserId::generate();
        assert!(validate_ticket_cookie(&secret, &u, "").is_none());
        assert!(validate_ticket_cookie(&secret, &u, "no-dot").is_none());
        assert!(validate_ticket_cookie(&secret, &u, "ticket.badmac").is_none());
    }

    #[test]
    fn append_query_handles_existing_queries() {
        assert_eq!(
            append_query("https://app/cb", &[("code", "abc"), ("state", "xyz")]),
            "https://app/cb?code=abc&state=xyz"
        );
        assert_eq!(
            append_query(
                "https://app/cb?foo=bar",
                &[("code", "abc"), ("state", "xyz")]
            ),
            "https://app/cb?foo=bar&code=abc&state=xyz"
        );
    }

    #[test]
    fn append_query_skips_empty_values() {
        assert_eq!(
            append_query(
                "https://app/cb",
                &[("code", "abc"), ("state", ""), ("other", "v")]
            ),
            "https://app/cb?code=abc&other=v"
        );
    }

    #[test]
    fn append_query_percent_encodes_reserved() {
        let out = append_query("https://app/cb", &[("state", "a b&c=d")]);
        assert!(out.contains("state=a%20b%26c%3Dd"), "got: {out}");
    }
}
