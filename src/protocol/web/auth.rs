//! Cookie-based authentication primitives for the web UI.
//!
//! This module owns the "session cookie" scheme used by `/ui/*`:
//!
//! * **Format:** the cookie value is `<session_id>.<realm_id>.<mac>`.
//!   The MAC is HMAC-SHA256 over `session_id|realm_id` with a 32-byte
//!   random key generated at startup.
//! * **Why:** Hearth's identity engine is realm-scoped — every call
//!   needs both a `SessionId` and a `RealmId`. Binding them in the
//!   cookie keeps the UI stateless (no per-session server lookup to
//!   resolve the realm) while making tampering trivially detectable.
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

use crate::core::{RealmId, SessionId, UserId};
use crate::identity::{IdentityEngine, Session};

use super::handlers_common::ForbiddenTemplate;
use super::templates::render_status;
use super::WebState;

/// Name of the server-only cookie carrying the session+realm binding.
pub const SESSION_COOKIE: &str = "hearth_ui_session";
/// Name of the page-readable cookie carrying the CSRF token.
pub const CSRF_COOKIE: &str = "hearth_ui_csrf";
/// Name of the cookie carrying the admin's currently-selected target
/// realm name.
///
/// Set by the realm switcher in the admin UI; read by [`TargetRealm`].
/// Does not need to be signed — the realm name is validated against
/// storage on every extraction, and a tampered cookie just yields the
/// wrong page (not an authentication bypass).
pub const ADMIN_TARGET_COOKIE: &str = "hearth_ui_admin_target";

/// Name of the short-lived cookie carrying the pending MFA challenge state.
///
/// Issued after successful password verification when MFA is enabled.
/// The value is `{user_id}.{realm_id}.{expires_unix_secs}.{return_to_b64}.{mac}`
/// where MAC = HMAC-SHA256(secret, `user_id|realm_id|expires|return_to_b64`).
/// TTL: 5 minutes.
pub const MFA_PENDING_COOKIE: &str = "hearth_ui_mfa_pending";

/// Name of the long-lived cookie that remembers the last realm a user
/// successfully signed in to.
///
/// Written by every successful sign-in handler (password, MFA, passkey,
/// magic-link) and refreshed on logout. Read by [`redirect_to_login`]
/// and [`login_url_for_realm`] so that an unauthenticated user is sent
/// back to the login page for their *previous* realm instead of the
/// ambiguous top-level `/ui/login` page (which errors out in multi-realm
/// deployments without a `default_realm_name`).
///
/// Not security-sensitive: a tampered value just produces a different
/// login page, never an auth bypass. The login form itself validates the
/// realm name against storage before proceeding.
///
/// Value: realm name (slug), or the [`SYSTEM_REALM_SENTINEL`] literal
/// when the user last signed in via `/ui/admin/login`.
pub const LAST_REALM_COOKIE: &str = "hearth_ui_last_realm";

/// Sentinel value stored in the `hearth_ui_last_realm` cookie when the
/// user's last sign-in was through the admin login (system realm).
///
/// Cannot collide with any real realm name because realm names are
/// validated as slugs (`^[a-z][a-z0-9-]*$`) and never contain `__`.
pub const SYSTEM_REALM_SENTINEL: &str = "__system__";

/// TTL for the last-realm cookie in seconds (1 year).
const LAST_REALM_TTL_SECS: u64 = 31_536_000;

/// TTL for the MFA pending cookie in seconds (5 minutes).
const MFA_PENDING_TTL_SECS: u64 = 300;

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

/// Exposes the raw secret bytes for sibling modules that need to compute
/// their own HMAC tags (e.g. the OAuth consent ticket cookie). Kept
/// `pub(super)` so it does not leak outside the web adapter.
pub(super) fn cookie_secret_bytes(secret: &CookieSecret) -> &[u8] {
    secret.as_bytes()
}

/// Exposes the 32-byte cookie secret for federation confirm-link HMAC.
/// Sibling module accessor — not part of the public API.
pub(super) fn cookie_secret_bytes_32(secret: &CookieSecret) -> &[u8; 32] {
    secret.as_bytes()
}

impl std::fmt::Debug for CookieSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CookieSecret(<redacted>)")
    }
}

/// Parsed contents of a valid MFA pending cookie.
#[derive(Debug, Clone)]
pub struct MfaPending {
    /// User who passed the password check.
    pub user_id: UserId,
    /// Realm the user belongs to.
    pub realm_id: RealmId,
    /// Optional `return_to` path to redirect after MFA completes.
    pub return_to: Option<String>,
}

/// Builds the full `Set-Cookie` header value for an MFA pending cookie.
///
/// The cookie proves "this user passed password verification" and is
/// valid for [`MFA_PENDING_TTL_SECS`]. It grants no access — only the
/// right to attempt the second authentication factor.
#[must_use]
pub fn issue_mfa_pending_cookie(
    secret: &CookieSecret,
    realm_id: &RealmId,
    user_id: &UserId,
    return_to: Option<&str>,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before epoch")
        .as_secs();
    let expires = now + MFA_PENDING_TTL_SECS;

    let return_to_b64 = match return_to {
        Some(r) if !r.is_empty() => BASE64URL_NOPAD.encode(r.as_bytes()),
        _ => String::new(),
    };

    let mac = compute_mfa_pending_mac(secret, user_id, realm_id, expires, &return_to_b64);
    let value = format!(
        "{}.{}.{expires}.{return_to_b64}.{mac}",
        user_id.as_uuid(),
        realm_id.as_uuid(),
    );

    format!(
        "{MFA_PENDING_COOKIE}={value}; HttpOnly; Path=/ui; SameSite=Lax; Max-Age={MFA_PENDING_TTL_SECS}"
    )
}

/// Parses and validates an MFA pending cookie value.
///
/// Returns `None` on any parse / MAC / expiry failure. Intentionally
/// opaque — callers redirect to `/ui/login` on `None`.
#[must_use]
pub fn parse_mfa_pending_cookie(secret: &CookieSecret, value: &str) -> Option<MfaPending> {
    let mut parts = value.splitn(5, '.');
    let uid_str = parts.next()?;
    let tid_str = parts.next()?;
    let expires_str = parts.next()?;
    let return_to_b64 = parts.next()?;
    let mac_str = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let uid: Uuid = uid_str.parse().ok()?;
    let tid: Uuid = tid_str.parse().ok()?;
    let expires: u64 = expires_str.parse().ok()?;

    let user_id = UserId::new(uid);
    let realm_id = RealmId::new(tid);

    // Verify MAC first (constant-time).
    let expected = compute_mfa_pending_mac(secret, &user_id, &realm_id, expires, return_to_b64);
    let mac_match: bool = expected.as_bytes().ct_eq(mac_str.as_bytes()).into();
    if !mac_match {
        return None;
    }

    // Check expiry.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before epoch")
        .as_secs();
    if now > expires {
        return None;
    }

    let return_to = if return_to_b64.is_empty() {
        None
    } else {
        let decoded = BASE64URL_NOPAD.decode(return_to_b64.as_bytes()).ok()?;
        Some(String::from_utf8(decoded).ok()?)
    };

    Some(MfaPending {
        user_id,
        realm_id,
        return_to,
    })
}

/// Returns the full `Set-Cookie` header value that clears the MFA pending cookie.
#[must_use]
pub fn clear_mfa_pending_cookie() -> String {
    format!("{MFA_PENDING_COOKIE}=; HttpOnly; Path=/ui; SameSite=Lax; Max-Age=0")
}

/// Computes the HMAC tag for an MFA pending cookie.
fn compute_mfa_pending_mac(
    secret: &CookieSecret,
    user_id: &UserId,
    realm_id: &RealmId,
    expires: u64,
    return_to_b64: &str,
) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts any 32-byte key");
    mac.update(user_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(expires.to_string().as_bytes());
    mac.update(b"|");
    mac.update(return_to_b64.as_bytes());
    let tag = mac.finalize().into_bytes();
    BASE64URL_NOPAD.encode(&tag)
}

/// Extracts a named cookie value from raw `HeaderMap` (not `Parts`).
///
/// Useful for pre-auth handlers that receive `HeaderMap` directly.
pub fn cookie_value_from_headers<'a>(
    headers: &'a axum::http::HeaderMap,
    name: &str,
) -> Option<&'a str> {
    let prefix = format!("{name}=");
    for value in headers.get_all(header::COOKIE) {
        let Ok(header_str) = value.to_str() else {
            continue;
        };
        for pair in header_str.split(';') {
            let trimmed = pair.trim();
            if let Some(v) = trimmed.strip_prefix(&prefix) {
                let ptr = v.as_ptr();
                let len = v.len();
                // SAFETY: same argument as `cookie_value` — the slice borrows
                // from `header_str` which borrows from the `HeaderValue` inside
                // `headers`, and `headers` lives for `'a`.
                let s: &'a str =
                    unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(ptr, len)) };
                return Some(s);
            }
        }
    }
    None
}

/// Cookie pair issued on a successful login.
pub struct IssuedCookies {
    /// Full `Set-Cookie` header value for the session cookie.
    pub session_cookie: String,
    /// Full `Set-Cookie` header value for the CSRF cookie.
    pub csrf_cookie: String,
}

/// Computes the HMAC tag for a `session_id|realm_id` pair.
fn compute_mac(secret: &CookieSecret, session_id: &SessionId, realm_id: &RealmId) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts any 32-byte key");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm_id.as_uuid().as_bytes());
    let tag = mac.finalize().into_bytes();
    BASE64URL_NOPAD.encode(&tag)
}

/// Builds the authenticated cookie pair for a freshly created session.
#[must_use]
pub fn issue_auth_cookies(
    secret: &CookieSecret,
    realm_id: &RealmId,
    session_id: &SessionId,
) -> IssuedCookies {
    let mac = compute_mac(secret, session_id, realm_id);
    let session_value = format!("{}.{}.{mac}", session_id.as_uuid(), realm_id.as_uuid());

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

/// Builds a `Set-Cookie` value that records the realm the user last
/// signed in to.
///
/// Pass [`SYSTEM_REALM_SENTINEL`] for admin (system-realm) sign-ins.
/// For regular sign-ins, pass the realm's slug/name.
#[must_use]
pub fn last_realm_cookie(realm_name: &str) -> String {
    format!(
        "{LAST_REALM_COOKIE}={realm_name}; Path=/ui; SameSite=Lax; Max-Age={LAST_REALM_TTL_SECS}"
    )
}

/// Resolves the value to store in the `hearth_ui_last_realm` cookie
/// for a given realm id.
///
/// Returns the [`SYSTEM_REALM_SENTINEL`] for the system realm, or the
/// realm's configured name for tenant realms. On engine errors (which
/// should not happen for a realm the caller is actively authenticating
/// against) falls back to the sentinel so future unauthenticated
/// requests land on a page that always renders.
#[must_use]
pub fn last_realm_value(
    identity: &dyn crate::identity::IdentityEngine,
    realm_id: &RealmId,
) -> String {
    if realm_id == &crate::identity::keys::system_realm_id() {
        return SYSTEM_REALM_SENTINEL.to_string();
    }
    match identity.get_realm(realm_id) {
        Ok(Some(realm)) => realm.name().to_string(),
        _ => SYSTEM_REALM_SENTINEL.to_string(),
    }
}

/// Builds the scoped login URL for a realm, or the unscoped
/// realm-required page if no realm context is known.
///
/// * `Some(name) == SYSTEM_REALM_SENTINEL` → `/ui/admin/login`
/// * `Some(name)` → `/ui/realms/{name}/login`
/// * `None` → `/ui/login` (realm-required landing page)
#[must_use]
pub fn login_url_for_realm(realm_name: Option<&str>) -> String {
    match realm_name {
        Some(name) if name == SYSTEM_REALM_SENTINEL => "/ui/admin/login".to_string(),
        Some(name) => format!("/ui/realms/{name}/login"),
        None => "/ui/login".to_string(),
    }
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
                let s: &'a str =
                    unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(ptr, len)) };
                return Some(s);
            }
        }
    }
    None
}

/// Parsed session cookie, validated and ready to use.
#[derive(Debug, Clone)]
pub struct UiSession {
    /// Realm the session belongs to (extracted from the cookie, MAC-checked).
    pub realm_id: RealmId,
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
/// `(session_id, realm_id)` pair on success, or `None` on any
/// parse / MAC / format failure.
#[must_use]
pub fn parse_session_cookie(secret: &CookieSecret, value: &str) -> Option<(SessionId, RealmId)> {
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
    let realm_id = RealmId::new(tid_uuid);

    let expected = compute_mac(secret, &session_id, &realm_id);
    // Constant-time compare.
    if expected.as_bytes().ct_eq(mac_str.as_bytes()).into() {
        Some((session_id, realm_id))
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

        let Some((session_id, realm_id)) = parse_session_cookie(&web_state.cookie_secret, raw)
        else {
            return Err(redirect_to_login(parts));
        };

        let session = match web_state.identity.get_session(&realm_id, &session_id) {
            Ok(Some(s)) => s,
            Ok(None) => return Err(redirect_to_login(parts)),
            Err(e) => {
                tracing::warn!(error = %e, "UiSession: get_session failed");
                return Err(redirect_to_login(parts));
            }
        };

        let Ok(Some(user)) = web_state.identity.get_user(&realm_id, session.user_id()) else {
            return Err(redirect_to_login(parts));
        };

        Ok(UiSession {
            realm_id,
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
    realm_id: &RealmId,
    session_id: &SessionId,
) -> Option<Session> {
    identity.get_session(realm_id, session_id).ok().flatten()
}

/// Extracts the application realm the admin is currently
/// administering — the `?realm=<name>` query parameter on admin URLs.
///
/// Admin sessions are always bound to the system realm
/// ([`crate::identity::keys::system_realm_id`]), which is not a place
/// for tenant users, OAuth clients, or organizations. The admin UI
/// operates on tenant realms via this extractor.
///
/// Resolution rules:
///
/// 1. If `?realm=<name>` is present and names an existing non-system
///    realm, use it.
/// 2. If `?realm=<name>` is present but names the reserved `system`
///    realm or a nonexistent realm, return 404.
/// 3. Otherwise, if the `hearth_ui_admin_target` cookie is set and
///    names an existing non-system realm, use it.
/// 4. Otherwise, fall back to the first realm returned by
///    [`crate::identity::IdentityEngine::list_realms`] (which already
///    filters out the system realm). Operators without any tenant
///    realm see 404; handlers should render a friendly "no realms
///    yet" state where applicable.
///
/// Callers that need to handle "no realms yet" specially can extract
/// [`Option<TargetRealm>`] instead and branch on `None`.
#[derive(Debug, Clone)]
pub struct TargetRealm(pub crate::identity::Realm);

impl TargetRealm {
    /// Returns the resolved `RealmId`.
    #[must_use]
    pub fn id(&self) -> &crate::core::RealmId {
        self.0.id()
    }

    /// Resolves a target realm by name against the identity engine.
    ///
    /// Used by handlers under `/ui/admin/realms/{realm_name}/*` that
    /// already extracted the path segment via
    /// [`axum::extract::Path`] and need a validated realm in hand.
    /// Rejects the reserved system realm name and any non-existent realm
    /// with a 404 response; handlers should `?`-bubble the error.
    ///
    /// # Errors
    ///
    /// Returns a rendered 404 `Response` for an unknown or reserved
    /// realm name, and a 500 `Response` on engine error.
    #[allow(clippy::result_large_err)]
    pub fn from_name(state: &Arc<WebState>, name: &str) -> Result<Self, Response> {
        resolve_named_realm(state, name)
    }
}

impl<S> FromRequestParts<S> for TargetRealm
where
    Arc<WebState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let web_state = Arc::<WebState>::from_ref(state);

        // Highest-priority source: the canonical
        // `/ui/admin/realms/{name}/...` path segment. When the URL names
        // a realm, it is the realm — no cookie or query override can
        // redirect the request elsewhere. This is what makes a
        // workspace URL share-able: two admins looking at the same link
        // see the same realm regardless of their individual cookies.
        if let Some(name) = path_realm_segment(parts.uri.path()) {
            return resolve_named_realm(&web_state, &name);
        }

        // Parse `?realm=<name>` from the URL query string. We don't
        // use axum's Query<T> extractor here so we can gracefully
        // accept admin URLs that carry many other unrelated query
        // params without having to define a catch-all struct.
        let query_realm = parts
            .uri
            .query()
            .and_then(|q| {
                q.split('&')
                    .find_map(|p| p.strip_prefix("realm="))
                    .map(|v| {
                        // URL-decode '+' and '%' escapes minimally — realm
                        // names are slug-ish so this usually returns the
                        // value unchanged.
                        percent_decode(v)
                    })
            })
            .filter(|s| !s.is_empty());

        // Try the query parameter first. Explicit URL overrides the
        // cookie so deep-links and share-links behave predictably.
        if let Some(name) = query_realm {
            return resolve_named_realm(&web_state, &name);
        }

        // Fall back to the admin-target cookie. Unsigned — a tampered
        // cookie just yields a different page, not an auth bypass, and
        // the engine validates the name before use.
        if let Some(name) = cookie_value(parts, ADMIN_TARGET_COOKIE) {
            let decoded = percent_decode(name);
            if !decoded.is_empty() && decoded != crate::identity::keys::SYSTEM_REALM_NAME {
                if let Ok(Some(realm)) = web_state.identity.get_realm_by_name(&decoded) {
                    return Ok(TargetRealm(realm));
                }
                // Cookie references a stale/deleted realm; fall through
                // to the first-realm default rather than 404.
            }
        }

        // Default: first non-system realm.
        match web_state.identity.list_realms(None, 1) {
            Ok(page) => match page.items.into_iter().next() {
                Some(realm) => Ok(TargetRealm(realm)),
                None => Err(render_status(
                    &super::handlers_common::NotFoundTemplate::new(
                        "No application realms exist yet. Declare one in hearth.yaml to begin."
                            .to_string(),
                    ),
                    StatusCode::NOT_FOUND,
                )),
            },
            Err(e) => {
                tracing::warn!(error = %e, "TargetRealm: list_realms failed");
                Err(render_status(
                    &super::handlers_common::ServerErrorTemplate::new(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        }
    }
}

/// Extracts the realm name from a URL path of the form
/// `/ui/admin/realms/{name}/...`.
///
/// Returns `None` for:
/// * The bare realm list at `/ui/admin/realms`.
/// * Admin realm detail at `/ui/admin/realms/{id}` where `{id}` is a
///   UUID (the legacy flat realm-detail page — realm names cannot look
///   like UUIDs because slug validation rejects them).
/// * Anything outside the `/ui/admin/realms/` prefix.
///
/// The returned name is not validated against storage; the caller must
/// still funnel it through [`resolve_named_realm`], which rejects the
/// reserved `system` name and unknown realms.
fn path_realm_segment(path: &str) -> Option<String> {
    // Accept both `/ui/admin/realms/{name}/...` and the nested form
    // where axum mounts `/admin/...` under `/ui`.
    let rest = path
        .strip_prefix("/ui/admin/realms/")
        .or_else(|| path.strip_prefix("/admin/realms/"))?;
    let name = rest.split('/').next()?;
    if name.is_empty() {
        return None;
    }
    // UUIDs indicate the legacy `/admin/realms/{id}` detail route.
    // Realm names cannot parse as UUIDs because the slug validator
    // rejects dashes-only / hex-only strings of that length.
    if uuid::Uuid::parse_str(name).is_ok() {
        return None;
    }
    // Only match paths that name a *sub-resource* under the realm —
    // the pattern is `/admin/realms/{name}/{sub}/...`. A bare
    // `/admin/realms/{name}` without a trailing segment is the
    // workspace overview page, which is handled separately.
    rest.find('/')?;
    Some(name.to_string())
}

/// Resolves a realm by name for the `TargetRealm` extractor. Rejects
/// the reserved system-realm name so an admin cannot accidentally
/// target the admin realm with `?realm=system`.
#[allow(clippy::result_large_err)] // Response is inherently ~128B; boxing on the rare failure path isn't worth the extra heap alloc on each successful call.
fn resolve_named_realm(web_state: &Arc<WebState>, name: &str) -> Result<TargetRealm, Response> {
    if name == crate::identity::keys::SYSTEM_REALM_NAME {
        return Err(render_status(
            &super::handlers_common::NotFoundTemplate::new("Realm not found.".to_string()),
            StatusCode::NOT_FOUND,
        ));
    }
    match web_state.identity.get_realm_by_name(name) {
        Ok(Some(realm)) => Ok(TargetRealm(realm)),
        Ok(None) => Err(render_status(
            &super::handlers_common::NotFoundTemplate::new("Realm not found.".to_string()),
            StatusCode::NOT_FOUND,
        )),
        Err(e) => {
            tracing::warn!(error = %e, realm = %name, "TargetRealm: get_realm_by_name failed");
            Err(render_status(
                &super::handlers_common::ServerErrorTemplate::new(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// Minimal percent-decoding for realm-name query values. Handles `+`
/// (space) and `%XX` escapes; returns the input unchanged on any
/// malformed sequence. Realm names are slug-ish so most callers will
/// get the value back verbatim.
fn percent_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte as char);
                    i += 3;
                } else {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// Like [`UiSession`] but additionally requires the caller has the
/// `hearth.admin` permission claim.
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

        // Admin sessions always live in the system realm. A tenant-realm
        // session cannot carry admin privilege; reject with 403 rather
        // than leak "the admin URL exists" by redirecting. The caller
        // shows the same page to tenant users whether they hit the URL
        // with or without a session.
        if session.realm_id != crate::identity::keys::system_realm_id() {
            return Err(render_status(
                &ForbiddenTemplate::new(Some(session.user_email.clone())),
                StatusCode::FORBIDDEN,
            ));
        }

        // Resolve the user's current permissions against the RBAC engine
        // (not the JWT claims) — session cookies don't carry claims, so
        // we check freshly at every admin request.
        let resolved = web_state
            .rbac
            .resolve_permissions(&session.user_id, &session.realm_id, None, None)
            .ok();
        let is_admin = resolved
            .map(|r| r.permissions.iter().any(|p| p.as_str() == "hearth.admin"))
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

/// Builds a 303 redirect to the best-fit login page for the current
/// request, preserving the original URL as `?return_to=`.
///
/// Resolution order for which login page to target:
///
/// 1. Request path starts with `/ui/admin/` → `/ui/admin/login`.
/// 2. Request path starts with `/ui/realms/{name}/` → that realm's
///    login page. The realm name is *not* validated here (the downstream
///    login handler does that) — mis-typed realm names fail loudly on
///    the login page itself, which is the right UX.
/// 3. `hearth_ui_last_realm` cookie is set → login page for that realm
///    (or the admin login if the sentinel is present).
/// 4. Fall back to `/ui/login`, which renders the
///    realm-required page in multi-realm deployments.
///
/// `return_to` is sanitized via [`sanitize_return_to`] and dropped if
/// unsafe; no open-redirect risk.
fn redirect_to_login(parts: &Parts) -> Response {
    let path = parts.uri.path();
    // The nested router under `/ui` strips the mount prefix before
    // handlers see the path. Re-prepend it for the `return_to` value so
    // the login form can safely round-trip it as a same-site absolute
    // path — `sanitize_return_to` requires the `/ui` prefix.
    let path_and_query = {
        let raw = parts
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), |p| p.as_str().to_string());
        if raw.starts_with("/ui") {
            raw
        } else if raw == "/" {
            "/ui".to_string()
        } else {
            format!("/ui{raw}")
        }
    };

    // Pick the login URL based on context. axum's nested router strips
    // the mount prefix before handlers see `parts.uri.path()`, so the
    // admin surface appears as `/admin/*` even though it's mounted at
    // `/ui/admin/*`. Accept both prefixes to handle nested and top-
    // level mounts uniformly.
    let is_admin = path.starts_with("/ui/admin/")
        || path == "/ui/admin"
        || path.starts_with("/admin/")
        || path == "/admin";
    let realm_in_path = path
        .strip_prefix("/ui/realms/")
        .or_else(|| path.strip_prefix("/realms/"));
    let login_path = if is_admin {
        login_url_for_realm(Some(SYSTEM_REALM_SENTINEL))
    } else if let Some(rest) = realm_in_path {
        // `/realms/{name}/...` — strip the first segment as the realm
        // name. Empty or missing segment falls through to the cookie
        // default below.
        let name = rest.split('/').next().unwrap_or("");
        if name.is_empty() {
            login_url_for_realm(realm_from_last_realm_cookie(parts).as_deref())
        } else {
            login_url_for_realm(Some(name))
        }
    } else {
        login_url_for_realm(realm_from_last_realm_cookie(parts).as_deref())
    };

    let sanitized = sanitize_return_to(&path_and_query).unwrap_or_else(|| "/ui".to_string());
    let encoded = url_encode(&sanitized);
    let location = format!("{login_path}?return_to={encoded}");

    let mut response = Redirect::to(&location).into_response();
    // 303 is already what axum::Redirect::to uses.
    if let Ok(v) = HeaderValue::from_str("no-store") {
        response.headers_mut().insert(header::CACHE_CONTROL, v);
    }
    response
}

/// Extracts the `hearth_ui_last_realm` cookie value as an owned string.
/// Returns `None` if the cookie is absent or empty.
fn realm_from_last_realm_cookie(parts: &Parts) -> Option<String> {
    cookie_value(parts, LAST_REALM_COOKIE)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
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

/// Percent-encodes a string for use as a single query-parameter VALUE.
///
/// Only the URI unreserved set (RFC 3986 §2.3) is passed through verbatim;
/// every other byte — including `?`, `=`, `&`, `/` — is percent-encoded.
/// `/` encodes to `%2F` rather than being preserved, since its role as a
/// path separator does not apply inside a query value.
///
/// Used when folding an original request URL into `?return_to=...` on a
/// login redirect: the whole return-to (path + query) has to survive
/// round-tripping through the login form as a single query value, which
/// means reserved query-component characters inside it MUST be escaped.
/// Passing `?`/`&`/`=` through unchanged corrupts the login form's query
/// string by turning inner OAuth params into siblings of `return_to`.
fn url_encode(input: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
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
        let tid = RealmId::new(Uuid::from_u128(0xAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_1234_5678));
        let mac = compute_mac(&secret, &sid, &tid);
        let value = format!("{}.{}.{mac}", sid.as_uuid(), tid.as_uuid());
        let parsed = parse_session_cookie(&secret, &value).expect("valid cookie");
        assert_eq!(parsed.0, sid);
        assert_eq!(parsed.1, tid);
    }

    #[test]
    fn mac_tag_detects_realm_substitution() {
        let secret = CookieSecret::from_bytes([9u8; 32]);
        let sid = SessionId::generate();
        let tid = RealmId::generate();
        let other = RealmId::generate();
        let mac = compute_mac(&secret, &sid, &tid);
        let tampered = format!("{}.{}.{mac}", sid.as_uuid(), other.as_uuid());
        assert!(parse_session_cookie(&secret, &tampered).is_none());
    }

    #[test]
    fn mac_tag_detects_session_substitution() {
        let secret = CookieSecret::from_bytes([3u8; 32]);
        let sid = SessionId::generate();
        let other = SessionId::generate();
        let tid = RealmId::generate();
        let mac = compute_mac(&secret, &sid, &tid);
        let tampered = format!("{}.{}.{mac}", other.as_uuid(), tid.as_uuid());
        assert!(parse_session_cookie(&secret, &tampered).is_none());
    }

    #[test]
    fn mac_detects_key_substitution() {
        let secret_a = CookieSecret::from_bytes([1u8; 32]);
        let secret_b = CookieSecret::from_bytes([2u8; 32]);
        let sid = SessionId::generate();
        let tid = RealmId::generate();
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

    // ===== MFA pending cookie tests =====

    #[test]
    fn mfa_pending_cookie_round_trip() {
        let secret = CookieSecret::from_bytes([5u8; 32]);
        let uid = UserId::generate();
        let tid = RealmId::generate();

        let full = issue_mfa_pending_cookie(&secret, &tid, &uid, None);
        // Extract value from `Set-Cookie` header.
        let value = full
            .strip_prefix(&format!("{MFA_PENDING_COOKIE}="))
            .expect("prefix")
            .split(';')
            .next()
            .expect("value");

        let parsed = parse_mfa_pending_cookie(&secret, value).expect("valid");
        assert_eq!(parsed.user_id, uid);
        assert_eq!(parsed.realm_id, tid);
        assert!(parsed.return_to.is_none());
    }

    #[test]
    fn mfa_pending_cookie_detects_user_id_tampering() {
        let secret = CookieSecret::from_bytes([6u8; 32]);
        let uid = UserId::generate();
        let other = UserId::generate();
        let tid = RealmId::generate();

        let full = issue_mfa_pending_cookie(&secret, &tid, &uid, None);
        let value = full
            .strip_prefix(&format!("{MFA_PENDING_COOKIE}="))
            .expect("prefix")
            .split(';')
            .next()
            .expect("value");

        // Replace the user_id segment with a different UUID.
        let tampered = value.replacen(&uid.as_uuid().to_string(), &other.as_uuid().to_string(), 1);
        assert!(
            parse_mfa_pending_cookie(&secret, &tampered).is_none(),
            "tampered user_id should be rejected"
        );
    }

    #[test]
    fn mfa_pending_cookie_detects_realm_id_tampering() {
        let secret = CookieSecret::from_bytes([7u8; 32]);
        let uid = UserId::generate();
        let tid = RealmId::generate();
        let other_tid = RealmId::generate();

        let full = issue_mfa_pending_cookie(&secret, &tid, &uid, None);
        let value = full
            .strip_prefix(&format!("{MFA_PENDING_COOKIE}="))
            .expect("prefix")
            .split(';')
            .next()
            .expect("value");

        // Replace the realm_id segment with a different UUID.
        let tampered = value.replacen(
            &tid.as_uuid().to_string(),
            &other_tid.as_uuid().to_string(),
            1,
        );
        assert!(
            parse_mfa_pending_cookie(&secret, &tampered).is_none(),
            "tampered realm_id should be rejected"
        );
    }

    #[test]
    fn mfa_pending_cookie_rejects_expired() {
        let secret = CookieSecret::from_bytes([8u8; 32]);
        let uid = UserId::generate();
        let tid = RealmId::generate();

        // Manually craft a cookie that expired 10 seconds ago.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("epoch")
            .as_secs();
        let expired = now.saturating_sub(10);
        let return_to_b64 = "";
        let mac = compute_mfa_pending_mac(&secret, &uid, &tid, expired, return_to_b64);
        let value = format!(
            "{}.{}.{expired}.{return_to_b64}.{mac}",
            uid.as_uuid(),
            tid.as_uuid(),
        );

        assert!(
            parse_mfa_pending_cookie(&secret, &value).is_none(),
            "expired cookie should be rejected"
        );
    }

    #[test]
    fn mfa_pending_cookie_preserves_return_to() {
        let secret = CookieSecret::from_bytes([9u8; 32]);
        let uid = UserId::generate();
        let tid = RealmId::generate();

        let full = issue_mfa_pending_cookie(&secret, &tid, &uid, Some("/ui/admin/users"));
        let value = full
            .strip_prefix(&format!("{MFA_PENDING_COOKIE}="))
            .expect("prefix")
            .split(';')
            .next()
            .expect("value");

        let parsed = parse_mfa_pending_cookie(&secret, value).expect("valid");
        assert_eq!(parsed.user_id, uid);
        assert_eq!(parsed.realm_id, tid);
        assert_eq!(parsed.return_to.as_deref(), Some("/ui/admin/users"));
    }
}
