//! In-process email catching transport for local development.
//!
//! Captures outbound emails in a ring-buffer inbox and exposes them via a
//! password-protected browser UI at `/dev/mail`. Auto-enabled when `--dev`
//! is passed and no explicit transport is configured.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::core::Timestamp;

use super::{reject_crlf, EmailError, EmailMessage, EmailSender};

/// Maximum number of emails retained in the inbox before evicting oldest.
pub const INBOX_CAP: usize = 50;

/// A captured email stored in the in-process inbox.
#[derive(Debug, Clone)]
pub struct CapturedEmail {
    /// Unique identifier for this email (UUIDv4).
    pub id: uuid::Uuid,
    /// Server-side timestamp (UTC microseconds) when the email was captured.
    pub received_at: Timestamp,
    /// Recipient address.
    pub to: String,
    /// Email subject.
    pub subject: String,
    /// HTML body.
    pub html_body: String,
    /// Plain-text body.
    pub text_body: String,
}

impl CapturedEmail {
    /// Returns the `received_at` timestamp formatted as `YYYY-MM-DD HH:MM:SS UTC`.
    pub fn received_at_display(&self) -> String {
        use time::format_description::well_known::Rfc3339;
        let nanos = i128::from(self.received_at.as_micros()) * 1000;
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .ok()
            .and_then(|dt| dt.format(&Rfc3339).ok())
            .unwrap_or_else(|| self.received_at.as_micros().to_string())
    }
}

/// Shared state for the mailcatcher transport and browser UI.
///
/// The `inbox` is a ring buffer shared between the [`MailcatcherSender`] and
/// the HTTP handlers. The `hmac_key` is derived deterministically from the
/// `password` so the same password always produces the same session cookie
/// (hot-reload compatible).
pub struct MailcatcherState {
    /// Ring buffer of captured emails (capped at [`INBOX_CAP`]).
    pub inbox: Mutex<VecDeque<CapturedEmail>>,
    /// Random password displayed at startup.
    pub password: String,
    /// HMAC-SHA256 key: `SHA-256("hearth-mcauth-v1" || password)`.
    pub hmac_key: [u8; 32],
}

impl MailcatcherState {
    /// Creates a new `MailcatcherState` with the given random password.
    ///
    /// The HMAC key is derived deterministically from the password.
    pub fn new(password: String) -> Self {
        let hmac_key = derive_hmac_key(&password);
        Self {
            inbox: Mutex::new(VecDeque::with_capacity(INBOX_CAP)),
            password,
            hmac_key,
        }
    }

    /// Returns the expected value for the `mcauth` session cookie.
    ///
    /// Value is `hex(HMAC-SHA256(hmac_key, "hearth-mcauth-session-v1"))`.
    /// Constant across the lifetime of this state so the browser session
    /// persists across config hot-reloads (same password → same cookie).
    pub fn session_cookie_value(&self) -> String {
        make_session_token(&self.hmac_key)
    }

    /// Returns `true` when `candidate` matches the expected session cookie.
    ///
    /// Uses constant-time comparison to prevent timing oracle attacks.
    pub fn verify_cookie(&self, candidate: &str) -> bool {
        let expected = self.session_cookie_value();
        ct_eq(expected.as_bytes(), candidate.as_bytes())
    }
}

impl std::fmt::Debug for MailcatcherState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailcatcherState")
            .field("inbox_len", &self.inbox.lock().map_or(0, |g| g.len()))
            .field("hmac_key", &"[redacted]")
            .field("password", &"[redacted]")
            .finish()
    }
}

/// An [`EmailSender`] that captures messages into a shared [`MailcatcherState`].
///
/// Maintains a ring buffer of up to [`INBOX_CAP`] messages; the oldest is
/// evicted when the inbox is full.
#[derive(Clone, Debug)]
pub struct MailcatcherSender {
    state: Arc<MailcatcherState>,
}

impl MailcatcherSender {
    /// Creates a new sender that writes to the given shared state.
    pub fn new(state: Arc<MailcatcherState>) -> Self {
        Self { state }
    }

    /// Returns a reference to the underlying [`MailcatcherState`].
    pub fn state(&self) -> &Arc<MailcatcherState> {
        &self.state
    }
}

impl EmailSender for MailcatcherSender {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        reject_crlf("recipient", &message.to)?;

        let email = CapturedEmail {
            id: uuid::Uuid::new_v4(),
            received_at: Timestamp::now(),
            to: message.to.clone(),
            subject: message.subject.clone(),
            html_body: message.html_body.clone(),
            text_body: message.text_body.clone(),
        };

        let mut inbox = self.state.inbox.lock().unwrap_or_else(|e| e.into_inner());
        if inbox.len() >= INBOX_CAP {
            inbox.pop_front();
        }
        inbox.push_back(email);
        Ok(())
    }
}

/// Derives the HMAC key: `SHA-256("hearth-mcauth-v1" || password)`.
///
/// Deterministic — same password always yields the same key.
pub fn derive_hmac_key(password: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"hearth-mcauth-v1");
    h.update(password.as_bytes());
    h.finalize().into()
}

/// Computes the `mcauth` session cookie value from an HMAC key.
fn make_session_token(hmac_key: &[u8; 32]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key length");
    mac.update(b"hearth-mcauth-session-v1");
    hex_encode(&mac.finalize().into_bytes())
}

/// Constant-time byte-slice equality. Returns `false` on length mismatch (safe:
/// length is not a secret in this context).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Encodes a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Generates a cryptographically random 16-character alphanumeric password.
///
/// Uses `ring::rand` so the entropy source is the same OS CSPRNG used
/// everywhere else in Hearth.
pub fn generate_password() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut bytes).expect("ring CSPRNG unavailable");
    bytes
        .iter()
        .map(|&b| CHARSET[usize::from(b) % CHARSET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unit: send() stores email ─────────────────────────────────────────

    #[test]
    fn send_stores_email_in_inbox() {
        let state = Arc::new(MailcatcherState::new("test-password".to_string()));
        let sender = MailcatcherSender::new(Arc::clone(&state));

        sender
            .send(&EmailMessage {
                to: "alice@example.com".to_string(),
                subject: "Hello".to_string(),
                html_body: "<p>Hi</p>".to_string(),
                text_body: "Hi".to_string(),
            })
            .expect("send should succeed");

        let inbox = state
            .inbox
            .lock()
            .expect("inbox lock should not be poisoned");
        assert_eq!(inbox.len(), 1, "inbox should contain one email");
        let email = &inbox[0];
        assert_eq!(email.to, "alice@example.com");
        assert_eq!(email.subject, "Hello");
        assert_eq!(email.html_body, "<p>Hi</p>");
        assert_eq!(email.text_body, "Hi");
    }

    // ── Unit: ring buffer evicts oldest at cap ────────────────────────────

    #[test]
    fn ring_buffer_evicts_oldest_at_cap() {
        let state = Arc::new(MailcatcherState::new("test-password".to_string()));
        let sender = MailcatcherSender::new(Arc::clone(&state));

        for i in 0..=50u32 {
            sender
                .send(&EmailMessage {
                    to: format!("user{i}@example.com"),
                    subject: format!("Email {i}"),
                    html_body: String::new(),
                    text_body: String::new(),
                })
                .expect("send should succeed");
        }

        let inbox = state
            .inbox
            .lock()
            .expect("inbox lock should not be poisoned");
        assert_eq!(inbox.len(), INBOX_CAP, "inbox must stay at cap");
        // user0 evicted; user1 is now the oldest
        assert_eq!(inbox[0].to, "user1@example.com", "oldest should be evicted");
        assert_eq!(
            inbox[INBOX_CAP - 1].to,
            "user50@example.com",
            "newest should be present"
        );
    }

    // ── Unit: HMAC key derivation is deterministic ────────────────────────

    #[test]
    fn hmac_key_derivation_is_deterministic() {
        let k1 = derive_hmac_key("supersecret");
        let k2 = derive_hmac_key("supersecret");
        assert_eq!(k1, k2, "same password must produce same key");
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let k1 = derive_hmac_key("password-a");
        let k2 = derive_hmac_key("password-b");
        assert_ne!(k1, k2, "different passwords must produce different keys");
    }

    // ── Unit: session cookie correctness ──────────────────────────────────

    #[test]
    fn session_cookie_is_deterministic_for_same_password() {
        let s1 = MailcatcherState::new("same-pw".to_string());
        let s2 = MailcatcherState::new("same-pw".to_string());
        assert_eq!(
            s1.session_cookie_value(),
            s2.session_cookie_value(),
            "same password → same cookie"
        );
    }

    #[test]
    fn verify_cookie_accepts_correct_value() {
        let state = MailcatcherState::new("test-pw".to_string());
        let cookie = state.session_cookie_value();
        assert!(
            state.verify_cookie(&cookie),
            "correct cookie should be accepted"
        );
    }

    #[test]
    fn verify_cookie_rejects_wrong_value() {
        let state = MailcatcherState::new("test-pw".to_string());
        assert!(
            !state.verify_cookie("wrong"),
            "wrong cookie must be rejected"
        );
        assert!(!state.verify_cookie(""), "empty cookie must be rejected");
    }

    // ── Unit: header injection rejected ──────────────────────────────────

    #[test]
    fn send_rejects_crlf_in_recipient() {
        let state = Arc::new(MailcatcherState::new("pw".to_string()));
        let sender = MailcatcherSender::new(state);
        let result = sender.send(&EmailMessage {
            to: "alice@x.com\r\nBcc: evil@x.com".to_string(),
            subject: "Test".to_string(),
            html_body: String::new(),
            text_body: String::new(),
        });
        assert!(
            matches!(result, Err(EmailError::InvalidInput { .. })),
            "CRLF in recipient must be rejected"
        );
    }
}
