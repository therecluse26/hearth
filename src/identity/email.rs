//! Outbound email delivery.
//!
//! Defines the [`EmailSender`] trait and a [`LoggingEmailSender`]
//! implementation that writes verification URLs to the `tracing` log at
//! WARN level. A future SMTP transport is an additive change — any new
//! backend just implements the same trait.
//!
//! Off the hot path. Senders are invoked from onboarding and (later)
//! password-reset flows, never from authentication.

use std::fmt;
use std::sync::Arc;

/// Errors returned from an email send attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum EmailError {
    /// The configured transport failed to deliver the message (network,
    /// auth, rejection). Contains a human-readable reason without secrets.
    Transport {
        /// Sanitized description of the failure.
        reason: String,
    },
    /// The caller passed an invalid recipient or body — e.g. an address
    /// containing CR/LF that would enable header injection.
    InvalidInput {
        /// What was wrong with the input.
        reason: String,
    },
}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { reason } => write!(f, "email transport error: {reason}"),
            Self::InvalidInput { reason } => write!(f, "invalid email input: {reason}"),
        }
    }
}

impl std::error::Error for EmailError {}

/// Trait for outbound email delivery.
///
/// Implementations MUST be `Send + Sync` so the sender can be held in an
/// `Arc` and called from any task. Implementations SHOULD reject inputs
/// containing CR/LF to prevent header injection.
pub trait EmailSender: Send + Sync {
    /// Sends a verification email containing `verification_url` to `to`.
    fn send_verification_email(&self, to: &str, verification_url: &str) -> Result<(), EmailError>;
}

/// Validates that an input string contains no CR/LF characters.
///
/// Email headers use CR/LF as separators; allowing untrusted input to
/// contain these characters enables header injection (e.g. adding a
/// `Bcc:` to exfiltrate mail to an attacker).
fn reject_crlf(field: &str, value: &str) -> Result<(), EmailError> {
    if value.contains('\r') || value.contains('\n') {
        return Err(EmailError::InvalidInput {
            reason: format!("{field} must not contain CR/LF"),
        });
    }
    Ok(())
}

/// An [`EmailSender`] that writes messages to the `tracing` log.
///
/// Default transport when no external mail server is configured. The
/// verification URL is emitted at WARN level so it stands out in normal
/// INFO-level logs. No PII is logged beyond the recipient address that
/// the caller already possesses.
#[derive(Debug, Default)]
pub struct LoggingEmailSender;

impl LoggingEmailSender {
    /// Creates a new logging sender.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl EmailSender for LoggingEmailSender {
    fn send_verification_email(&self, to: &str, verification_url: &str) -> Result<(), EmailError> {
        reject_crlf("recipient", to)?;
        reject_crlf("verification_url", verification_url)?;
        tracing::warn!(
            recipient = %to,
            verification_url = %verification_url,
            "email.send_verification (log transport): deliver this URL to the recipient"
        );
        Ok(())
    }
}

/// Convenience alias for a shared dynamic [`EmailSender`].
pub type SharedEmailSender = Arc<dyn EmailSender>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logging_sender_accepts_plain_values() {
        let sender = LoggingEmailSender::new();
        let result = sender.send_verification_email(
            "alice@example.com",
            "https://auth.example.com/ui/verify-email?token=abc",
        );
        assert!(result.is_ok(), "clean inputs should succeed: {result:?}");
    }

    #[test]
    fn rejects_header_injection_in_recipient() {
        let sender = LoggingEmailSender::new();
        let result = sender.send_verification_email("alice@x.com\r\nBcc: evil@x.com", "https://x/");
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
    }

    #[test]
    fn rejects_header_injection_in_url() {
        let sender = LoggingEmailSender::new();
        let result = sender
            .send_verification_email("alice@example.com", "https://x/\r\nContent-Type: text/html");
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
    }

    #[test]
    fn error_display_does_not_leak_secrets() {
        let err = EmailError::Transport {
            reason: "connection refused".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("email transport error"), "got: {display}");
        assert!(display.contains("connection refused"), "got: {display}");
    }

    #[test]
    fn email_sender_is_object_safe() {
        fn assert_object_safe(_: &dyn EmailSender) {}
        let sender = LoggingEmailSender::new();
        assert_object_safe(&sender);
    }
}
