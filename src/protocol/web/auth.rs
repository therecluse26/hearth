//! Cookie-based authentication primitives for the web UI.
//!
//! This module owns the "session cookie" scheme used by `/ui/*`:
//!
//! * **Format:** the cookie value is `<session_id>.<tenant_id>.<mac>`.
//!   The MAC is HMAC-SHA256 over `session_id|tenant_id` with a 32-byte
//!   random key generated at startup.
//! * **Why:** Hearth's identity engine is tenant-scoped — every call
//!   needs both a `SessionId` and a `TenantId`. Binding them in the
//!   cookie keeps the UI stateless (no per-session server lookup to
//!   resolve the tenant) while making tampering trivially detectable.
//! * **CSRF:** the second cookie (`hearth_ui_csrf`) is a 32-byte random
//!   value. The page reads it via JS and echoes it on every mutation
//!   (form field `_csrf` or `X-CSRF-Token` HTMX header). The extractor
//!   constant-time compares. See [`CsrfToken::from_request_parts`].
//!
//! The format is intentionally simple: no JSON, no cbor — `.` works as
//! a separator because UUIDs and base64url chunks never contain `.`.
//!
//! # What this module is *not*
//!
//! This is not a generic cookie library — we only need what the UI
//! uses. In particular:
//!
//! * No rolling secret rotation (would require secret *versioning*).
//!   Restarting the server invalidates every logged-in UI session;
//!   that's acceptable for an admin console.
//! * No `Secure` flag when TLS is off — the config-layer TLS flag is
//!   already what gates that. The `SameSite=Lax` + `HttpOnly` combo
//!   is sufficient defense-in-depth regardless.

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::core::{SessionId, TenantId, UserId};
use crate::identity::{IdentityEngine, Session};

use super::handlers_common::ForbiddenTemplate;
use super::templates::render_status;
use super::WebState;

/// Name of the server-only cookie carrying the session+tenant binding.
pub const SESSION_COOKIE: &str = "hearth_ui_session";
/// Name of the page-readable cookie carrying the CSRF token.
pub const CSRF_COOKIE: &str = "hearth_ui_csrf";

/// Secret used to MAC session cookies. 32 random bytes. Shared across
/// all UI handlers via [`WebState::cookie_secret`].
#[derive(Clone)]
pub struct CookieSecret(Arc<[u8; 32]>);

impl CookieSecret {
    /// Generates a fresh secret from the system CSPRNG.
    ///
    /// # Panics
    ///
    /// Panics only if the OS RNG is unavailable, which in practice
    /// means the process cannot make forward progress anyway.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        // INVARIANT: `ring::rand::SystemRandom::fill` returns `Err` only on
        // catastrophic OS RNG failure, at which point the process
        // cannot proceed safely.
        #[allow(clippy::unwrap_used)]
        SystemRandom::new().fill(&mut bytes).unwrap();
        Self(Arc::new(bytes))
    }

    /// Construct from a caller-supplied byte string. Used in tests.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Arc::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for CookieSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CookieSecret(<redacted>)")
    }
}

/// Cookie pair issued on a successful login.
pub struct IssuedCookies {
    /// Full `Set-Cookie` header value for the session cookie.
    pub session_cookie: String,
    /// Full `Set-Cookie` header value for the CSRF cookie.
    pub csrf_cookie: String,
}

/// Computes the HMAC tag for a `session_id|tenant_id` pair.
fn compute_mac(secret: &CookieSecret, session_id: &SessionId, tenant_id: &TenantId) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts any 32-byte key");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(tenant_id.as_uuid().as_bytes());
    let tag = mac.finalize().into_bytes();
    BASE64URL_NOPAD.encode(&tag)
}

/// Builds the authenticated cookie pair for a freshly created session.
#[must_use]
pub fn issue_auth_cookies(
    secret: &CookieSecret,
    tenant_id: &TenantId,
    session_id: &SessionId,
) -> IssuedCookies {
    let mac = compute_mac(secret, session_id, tenant_id);
    let session_value = format!("{}.{}.{mac}", session_id.as_uuid(), tenant_id.as_uuid());

    let mut csrf_bytes = [0u8; 32];
    // INVARIANT: see CookieSecret::random().
    #[allow(clippy::unwrap_used)]
    SystemRandom::new().fill(&mut csrf_bytes).unwrap();
    let csrf_value = BASE64URL_NOPAD.encode(&csrf_bytes);

    IssuedCookies {
        session_cookie: format!(
            "{SESSION_COOKIE}={session_value}; HttpOnly; Path=/ui; SameSite=Lax"
        ),
        // Note: no HttpOnly — the page reads it for HTMX headers.
        csrf_cookie: format!("{CSRF_COOKIE}={csrf_value}; Path=/ui; SameSite=Lax"),
    }
}

/// Returns the full `Set-Cookie` header values that clear both cookies.
#[must_use]
pub fn clearing_cookies() -> [String; 2] {
    [
        format!("{SESSION_COOKIE}=; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=0"),
        format!("{CSRF_COOKIE}=; Path=/ui; SameSite=Lax; Max-Age=0"),
    ]
}

/// Parses `Cookie` header(s) on a request and returns the value of the
/// named cookie, if present.
fn cookie_value<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    for value in parts.headers.get_all(header::COOKIE) {
        let Ok(header_str) = value.to_str() else {
            continue;
        };
        for pair in header_str.split(';') {
            let trimmed = pair.trim();
            if let Some(v) = trimmed.strip_prefix(&prefix) {
                // Transmute lifetime: `v` borrows from `header_str`,
                // which in turn borrows from `parts`. We mint a
                // reference bound to `'a` directly.
                let ptr = v.as_ptr();
                let len = v.len();
                // SAFETY: `v` is a slice of `header_str` which is itself
                // a slice of the underlying `HeaderValue` bytes, and the
                // `HeaderValue` lives for `'a` inside `parts.headers`.
                // We preserve the pointer, length, and UTF-8 invariant.
                let s: &'a str = unsafe {
                    std::str::from_utf8_unchecked(std::slice::from_raw_parts(ptr, len))
                };
                return Some(s);
            }
        }
    }
    None
}

/// Parsed session cookie, validated and ready to use.
#[derive(Debug, Clone)]
pub struct UiSession {
    /// Tenant the session belongs to (extracted from the cookie, MAC-checked).
    pub tenant_id: TenantId,
    /// Session id — can be looked up via `IdentityEngine::get_session`.
    pub session_id: SessionId,
    /// Owning user (resolved server-side from the session record).
    pub user_id: UserId,
    /// Email of the owning user, cached for rendering.
    pub user_email: String,
    /// Display name of the owning user.
    pub user_display_name: String,
    /// CSRF token read from the `hearth_ui_csrf` cookie, if present.
    ///
    /// Embedded in every rendered page via a `<meta name="csrf">` tag
    /// and an `hx-headers` attribute so HTMX requests echo it back on
    /// every mutation.
    pub csrf: Option<String>,
}

/// Parses and verifies the session cookie. Returns the underlying
/// `(session_id, tenant_id)` pair on success, or `None` on any
/// parse / MAC / format failure.
#[must_use]
pub fn parse_session_cookie(secret: &CookieSecret, value: &str) -> Option<(SessionId, TenantId)> {
    let mut parts = value.splitn(3, '.');
    let sid_str = parts.next()?;
    let tid_str = parts.next()?;
    let mac_str = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let sid_uuid: Uuid = sid_str.parse().ok()?;
    let tid_uuid: Uuid = tid_str.parse().ok()?;
    let session_id = SessionId::new(sid_uuid);
    let tenant_id = TenantId::new(tid_uuid);

    let expected = compute_mac(secret, &session_id, &tenant_id);
    // Constant-time compare.
    if expected.as_bytes().ct_eq(mac_str.as_bytes()).into() {
        Some((session_id, tenant_id))
    } else {
        None
    }
}

impl<S> FromRequestParts<S> for UiSession
where
    Arc<WebState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let web_state = Arc::<WebState>::from_ref(state);

        let Some(raw) = cookie_value(parts, SESSION_COOKIE) else {
            return Err(redirect_to_login(parts));
        };

        let Some((session_id, tenant_id)) = parse_session_cookie(&web_state.cookie_secret, raw)
        else {
            return Err(redirect_to_login(parts));
        };

        let session = match web_state.identity.get_session(&tenant_id, &session_id) {
            Ok(Some(s)) => s,
            Ok(None) => return Err(redirect_to_login(parts)),
            Err(e) => {
                tracing::warn!(error = %e, "UiSession: get_session failed");
                return Err(redirect_to_login(parts));
            }
        };

        let Ok(Some(user)) = web_state.identity.get_user(&tenant_id, session.user_id()) else {
            return Err(redirect_to_login(parts));
        };

        Ok(UiSession {
            tenant_id,
            session_id: session.id().clone(),
            user_id: session.user_id().clone(),
            user_email: user.email().to_string(),
            user_display_name: user.display_name().to_string(),
            csrf: cookie_value(parts, CSRF_COOKIE).map(ToString::to_string),
        })
    }
}

/// Access the raw `Session` record during extraction. Used in places
/// that need created / expires timestamps (e.g. the admin sessions
/// page).
#[must_use]
pub fn resolve_session(
    identity: &dyn IdentityEngine,
    tenant_id: &TenantId,
    session_id: &SessionId,
) -> Option<Session> {
    identity.get_session(tenant_id, session_id).ok().flatten()
}

/// Like [`UiSession`] but additionally requires the caller has the
/// `hearth#admin` relation in Zanzibar.
#[derive(Debug, Clone)]
pub struct RequireAdmin(pub UiSession);

impl<S> FromRequestParts<S> for RequireAdmin
where
    Arc<WebState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = UiSession::from_request_parts(parts, state).await?;
        let web_state = Arc::<WebState>::from_ref(state);

        // INVARIANT: "hearth"/"admin"/"user" are valid ObjectRef
        // components (short ASCII strings).
        #[allow(clippy::unwrap_used)]
        let object = crate::authz::ObjectRef::new("hearth", "admin").unwrap();
        #[allow(clippy::unwrap_used)]
        let subject =
            crate::authz::SubjectRef::direct("user", &session.user_id.as_uuid().to_string())
                .unwrap();

        let is_admin = web_state
            .authz
            .check(&session.tenant_id, &object, "admin", &subject, None)
            .unwrap_or(false);

        if is_admin {
            Ok(RequireAdmin(session))
        } else {
            Err(render_status(
                &ForbiddenTemplate::new(Some(session.user_email.clone())),
                StatusCode::FORBIDDEN,
            ))
        }
    }
}

/// Extractor that verifies the double-submit CSRF token on mutation
/// requests (POST/PUT/DELETE). GET and HEAD are pass-through.
///
/// The token is sourced from (in order):
/// 1. the `X-CSRF-Token` request header (used by HTMX), or
/// 2. a form field named `_csrf` parsed from the body.
///
/// The extractor only checks the header form — handlers that accept
/// form submissions that do not set the HTMX header MUST additionally
/// verify the `_csrf` field against [`UiSession::csrf`] before
/// performing any mutation. [`verify_csrf_form_field`] is the shared
/// helper for that check.
#[derive(Debug)]
pub struct CsrfToken;

impl<S> FromRequestParts<S> for CsrfToken
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let method = parts.method.clone();
        if !method_mutates(&method) {
            return Ok(CsrfToken);
        }

        let Some(cookie) = cookie_value(parts, CSRF_COOKIE) else {
            return Err(csrf_failure_response());
        };

        // Check the header first (HTMX path). If absent, defer to the
        // form-field check that the handler must perform.
        let header_val = parts
            .headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok());

        if let Some(h) = header_val {
            if ct_eq_str(h, cookie) {
                return Ok(CsrfToken);
            }
            return Err(csrf_failure_response());
        }

        // No header: accept so the handler can check the form field.
        Ok(CsrfToken)
    }
}

/// Confirms that a form-submitted `_csrf` field equals the cookie
/// value stored on the extracted session. Returns `Ok(())` on match,
/// `Err(Response)` with a 403 body otherwise.
#[allow(clippy::result_large_err)] // `Response` ~128 bytes; boxing costs a heap alloc on every failure
pub fn verify_csrf_form_field(session: &UiSession, submitted: &str) -> Result<(), Response> {
    match session.csrf.as_deref() {
        Some(cookie) if ct_eq_str(cookie, submitted) => Ok(()),
        _ => Err(csrf_failure_response()),
    }
}

fn method_mutates(method: &Method) -> bool {
    matches!(
        method,
        &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH
    )
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    // Length-independent compare: short circuits on length mismatch
    // but that's still constant-time *within* the comparison itself.
    // Observing the length is unavoidable with untyped strings.
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    a_bytes.ct_eq(b_bytes).into()
}

fn csrf_failure_response() -> Response {
    let tmpl = ForbiddenTemplate::new(None);
    render_status(&tmpl, StatusCode::FORBIDDEN)
}

/// Builds a 303 redirect to `/ui/login?return_to=<current_path>`.
fn redirect_to_login(parts: &Parts) -> Response {
    let path_and_query = parts.uri.path_and_query().map_or_else(
        || "/ui/".to_string(),
        |p| p.as_str().to_string(),
    );

    let sanitized = sanitize_return_to(&path_and_query).unwrap_or_else(|| "/ui/".to_string());
    let encoded = url_encode(&sanitized);
    let location = format!("/ui/login?return_to={encoded}");

    let mut response = Redirect::to(&location).into_response();
    // 303 is already what axum::Redirect::to uses.
    if let Ok(v) = HeaderValue::from_str("no-store") {
        response.headers_mut().insert(header::CACHE_CONTROL, v);
    }
    response
}

/// Normalises a `return_to` value so attackers cannot use it as an open
/// redirect. Returns `None` if the value is not a safe same-site path.
#[must_use]
pub fn sanitize_return_to(value: &str) -> Option<String> {
    let trimmed = value.trim();
    // Reject empty, non-root, and protocol-relative redirects.
    if !trimmed.starts_with('/') || trimmed.starts_with("//") {
        return None;
    }
    // Restrict to the UI surface.
    if !trimmed.starts_with("/ui/") && trimmed != "/ui" {
        return None;
    }
    // Reject newline/CR to avoid header injection via Location.
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return None;
    }
    Some(trimmed.to_string())
}

/// Minimal URL percent-encoder for path+query strings we control.
fn url_encode(input: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b'?'
            | b'=' | b'&' => out.push(b as char),
            _ => {
                // INVARIANT: writing to `String` via `fmt::Write` is infallible.
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_tag_matches_round_trip() {
        let secret = CookieSecret::from_bytes([7u8; 32]);
        let sid = SessionId::new(Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888));
        let tid = TenantId::new(Uuid::from_u128(0xAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_1234_5678));
        let mac = compute_mac(&secret, &sid, &tid);
        let value = format!("{}.{}.{mac}", sid.as_uuid(), tid.as_uuid());
        let parsed = parse_session_cookie(&secret, &value).expect("valid cookie");
        assert_eq!(parsed.0, sid);
        assert_eq!(parsed.1, tid);
    }

    #[test]
    fn mac_tag_detects_tenant_substitution() {
        let secret = CookieSecret::from_bytes([9u8; 32]);
        let sid = SessionId::generate();
        let tid = TenantId::generate();
        let other = TenantId::generate();
        let mac = compute_mac(&secret, &sid, &tid);
        let tampered = format!("{}.{}.{mac}", sid.as_uuid(), other.as_uuid());
        assert!(parse_session_cookie(&secret, &tampered).is_none());
    }

    #[test]
    fn mac_tag_detects_session_substitution() {
        let secret = CookieSecret::from_bytes([3u8; 32]);
        let sid = SessionId::generate();
        let other = SessionId::generate();
        let tid = TenantId::generate();
        let mac = compute_mac(&secret, &sid, &tid);
        let tampered = format!("{}.{}.{mac}", other.as_uuid(), tid.as_uuid());
        assert!(parse_session_cookie(&secret, &tampered).is_none());
    }

    #[test]
    fn mac_detects_key_substitution() {
        let secret_a = CookieSecret::from_bytes([1u8; 32]);
        let secret_b = CookieSecret::from_bytes([2u8; 32]);
        let sid = SessionId::generate();
        let tid = TenantId::generate();
        let mac_a = compute_mac(&secret_a, &sid, &tid);
        let value = format!("{}.{}.{mac_a}", sid.as_uuid(), tid.as_uuid());
        assert!(parse_session_cookie(&secret_b, &value).is_none());
    }

    #[test]
    fn parse_rejects_malformed_values() {
        let secret = CookieSecret::from_bytes([1u8; 32]);
        assert!(parse_session_cookie(&secret, "").is_none());
        assert!(parse_session_cookie(&secret, "onlyone").is_none());
        assert!(parse_session_cookie(&secret, "one.two").is_none());
        assert!(parse_session_cookie(&secret, "one.two.three.four").is_none());
        assert!(parse_session_cookie(&secret, "not-a-uuid.not-a-uuid.mac").is_none());
    }

    #[test]
    fn ct_eq_str_behaves_like_eq_for_equal_inputs() {
        assert!(ct_eq_str("abc", "abc"));
        assert!(!ct_eq_str("abc", "abd"));
        assert!(!ct_eq_str("abc", "abcd"));
        assert!(ct_eq_str("", ""));
    }

    #[test]
    fn sanitize_return_to_accepts_ui_paths() {
        assert_eq!(
            sanitize_return_to("/ui/admin/users"),
            Some("/ui/admin/users".to_string())
        );
        assert_eq!(sanitize_return_to("/ui"), Some("/ui".to_string()));
    }

    #[test]
    fn sanitize_return_to_rejects_open_redirects() {
        assert!(sanitize_return_to("//evil.com/phish").is_none());
        assert!(sanitize_return_to("https://evil.com").is_none());
        assert!(sanitize_return_to("/admin/api").is_none());
        assert!(sanitize_return_to("javascript:alert(1)").is_none());
        assert!(sanitize_return_to("/ui/\r\nSet-Cookie: evil").is_none());
    }
}
