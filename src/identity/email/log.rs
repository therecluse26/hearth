//! Logging email sender — writes messages to the `tracing` log.
//!
//! Default transport when no external mail server is configured. The
//! message details are emitted at WARN level so they stand out in normal
//! INFO-level logs. No PII is logged beyond the recipient address that
//! the caller already possesses.

use super::{reject_crlf, EmailError, EmailMessage, EmailSender};

/// An [`EmailSender`] that writes messages to the `tracing` log.
///
/// Default transport when no external mail server is configured.
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
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        reject_crlf("recipient", &message.to)?;
        tracing::warn!(
            recipient = %message.to,
            subject  = %message.subject,
            body     = %message.text_body,
            "email.send (log transport): message logged instead of delivered"
        );
        Ok(())
    }
}
