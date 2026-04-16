//! Outbound email delivery.
//!
//! Defines the [`EmailSender`] trait with two concrete implementations:
//!
//! - [`LoggingEmailSender`] — writes verification URLs to the `tracing`
//!   log at WARN level. The default for local development.
//! - [`SmtpEmailSender`] — delivers via SMTP (with or without TLS /
//!   STARTTLS) using the `lettre` crate. Production transport.
//!
//! Off the hot path. Senders are invoked from onboarding and (later)
//! password-reset flows, never from authentication.

use std::fmt;
use std::sync::Arc;

use lettre::{
    message::{header::ContentType, Mailbox, Message},
    transport::smtp::{authentication::Credentials, SmtpTransport},
    Transport,
};

use crate::config::{EmailConfig, SmtpEncryption};

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

/// An [`EmailSender`] that delivers messages via SMTP.
///
/// Generic over the underlying `lettre::Transport` so tests can drive
/// the sender with `lettre::transport::stub::StubTransport`, bypassing
/// any network I/O. Production code uses [`smtp_sender_from_config`]
/// which pins `T = SmtpTransport`.
///
/// # Blocking behavior
///
/// `lettre::SmtpTransport::send` is a blocking call — it opens a TCP
/// connection, negotiates TLS, runs the SMTP dialogue, and waits for
/// the server's `250` response. That can take several seconds on first
/// use. Because [`EmailSender`] is a sync trait that happens to be
/// called from async handlers, [`send_verification_email`] guards the
/// underlying `send` with `tokio::task::block_in_place` when a
/// multi-threaded Tokio runtime is detected. On current-thread runtimes
/// and in non-Tokio callers (including unit tests with `StubTransport`)
/// the send runs directly.
///
/// [`send_verification_email`]: EmailSender::send_verification_email
pub struct SmtpEmailSender<T>
where
    T: Transport + Send + Sync,
    T::Error: fmt::Display,
{
    transport: T,
    from: Mailbox,
}

impl<T> SmtpEmailSender<T>
where
    T: Transport + Send + Sync,
    T::Error: fmt::Display,
{
    /// Constructs a new `SmtpEmailSender` from an already-built transport.
    ///
    /// Prefer [`smtp_sender_from_config`] for production use; this
    /// constructor exists for test code that wants to plug in a
    /// `StubTransport`.
    pub fn new(transport: T, from: Mailbox) -> Self {
        Self { transport, from }
    }
}

impl<T> fmt::Debug for SmtpEmailSender<T>
where
    T: Transport + Send + Sync,
    T::Error: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpEmailSender")
            .field("from", &self.from.to_string())
            .finish_non_exhaustive()
    }
}

impl<T> EmailSender for SmtpEmailSender<T>
where
    T: Transport + Send + Sync,
    T::Error: fmt::Display,
{
    fn send_verification_email(&self, to: &str, verification_url: &str) -> Result<(), EmailError> {
        reject_crlf("recipient", to)?;
        reject_crlf("verification_url", verification_url)?;

        let to_mailbox: Mailbox =
            to.parse().map_err(
                |e: lettre::address::AddressError| EmailError::InvalidInput {
                    reason: format!("recipient: {e}"),
                },
            )?;

        let msg = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
            .subject("Verify your Hearth account")
            .header(ContentType::TEXT_PLAIN)
            .body(format!(
                "Click the link below to verify your account:\n\n{verification_url}\n\n\
                 If you didn't request this, you can safely ignore this message.\n"
            ))
            .map_err(|e| EmailError::InvalidInput {
                reason: e.to_string(),
            })?;

        // Sync `send` on lettre's SmtpTransport is blocking (TCP + TLS +
        // SMTP dialogue). Guard with `block_in_place` on the multi-thread
        // runtime so we don't starve the tokio worker. For the current-
        // thread runtime (cfg(tokio-unstable) or test configurations)
        // block_in_place would panic, so we fall through to a direct
        // call.
        let send_sync = || self.transport.send(&msg);
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(send_sync)
            }
            _ => send_sync(),
        };

        result.map_err(|e| EmailError::Transport {
            reason: e.to_string(),
        })?;

        tracing::info!(
            recipient = %to,
            "email.send_verification: delivered via SMTP"
        );
        Ok(())
    }
}

/// Builds a production [`SmtpEmailSender`] from an [`EmailConfig`].
///
/// The caller is responsible for passing a config whose `transport` is
/// [`crate::config::EmailTransport::Smtp`]; validation has already
/// confirmed that `from` and `smtp` are both present and well-formed.
///
/// Returns an error only in the unlikely case that the config passes
/// validation but `lettre` rejects the host when building the relay
/// (e.g. a resolver error during startup).
pub fn smtp_sender_from_config(
    cfg: &EmailConfig,
) -> Result<SmtpEmailSender<SmtpTransport>, EmailError> {
    let smtp = cfg.smtp.as_ref().ok_or_else(|| EmailError::InvalidInput {
        reason: "email.smtp block is required for SMTP transport".to_string(),
    })?;

    let from_str = cfg.from.as_ref().ok_or_else(|| EmailError::InvalidInput {
        reason: "email.from is required for SMTP transport".to_string(),
    })?;
    let from: Mailbox =
        from_str.parse().map_err(
            |e: lettre::address::AddressError| EmailError::InvalidInput {
                reason: format!("email.from: {e}"),
            },
        )?;

    let builder = match smtp.encryption {
        SmtpEncryption::None => SmtpTransport::builder_dangerous(&smtp.host),
        SmtpEncryption::Starttls => {
            SmtpTransport::starttls_relay(&smtp.host).map_err(|e| EmailError::Transport {
                reason: format!("starttls relay setup: {e}"),
            })?
        }
        SmtpEncryption::Tls => {
            SmtpTransport::relay(&smtp.host).map_err(|e| EmailError::Transport {
                reason: format!("tls relay setup: {e}"),
            })?
        }
    };

    let mut builder = builder.port(smtp.port);

    if let (Some(u), Some(p)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
    }

    Ok(SmtpEmailSender {
        transport: builder.build(),
        from,
    })
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

    // ===== SmtpEmailSender tests (StubTransport, no network) =====

    use lettre::transport::stub::StubTransport;

    fn stub_sender(stub: StubTransport) -> SmtpEmailSender<StubTransport> {
        let from: Mailbox = "Hearth <auth@example.com>"
            .parse()
            .expect("static mailbox parses");
        SmtpEmailSender::new(stub, from)
    }

    #[test]
    fn smtp_sender_delivers_well_formed_message() {
        let stub = StubTransport::new_ok();
        let sender = stub_sender(stub.clone());

        sender
            .send_verification_email(
                "Alice <alice@example.com>",
                "https://auth.example/verify?t=abc",
            )
            .expect("send should succeed with stub transport");

        let messages = stub.messages();
        assert_eq!(messages.len(), 1, "exactly one message delivered");
        let (envelope, body) = &messages[0];

        // Envelope: from and to are as configured.
        assert!(
            envelope
                .from()
                .is_some_and(|f| f.to_string() == "auth@example.com"),
            "envelope from should be auth@example.com, got {:?}",
            envelope.from()
        );
        let to: Vec<String> = envelope.to().iter().map(ToString::to_string).collect();
        assert_eq!(to, vec!["alice@example.com".to_string()]);

        // RFC 5322 body contains the expected headers and URL.
        assert!(
            body.contains("Subject: Verify your Hearth account"),
            "body: {body}"
        );
        assert!(
            body.contains("<auth@example.com>"),
            "missing From addr-spec: {body}"
        );
        assert!(
            body.contains("<alice@example.com>"),
            "missing To addr-spec: {body}"
        );
        assert!(body.contains("Hearth"), "missing From display-name: {body}");
        assert!(body.contains("Alice"), "missing To display-name: {body}");
        assert!(
            body.contains("https://auth.example/verify?t=abc"),
            "verification URL missing from body: {body}"
        );
    }

    #[test]
    fn smtp_sender_rejects_crlf_in_recipient() {
        let stub = StubTransport::new_ok();
        let sender = stub_sender(stub.clone());

        let result = sender.send_verification_email(
            "alice@example.com\r\nBcc: attacker@example.com",
            "https://auth.example/verify?t=abc",
        );
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
        assert_eq!(stub.messages().len(), 0, "no message should be sent");
    }

    #[test]
    fn smtp_sender_rejects_crlf_in_verification_url() {
        let stub = StubTransport::new_ok();
        let sender = stub_sender(stub.clone());

        let result = sender.send_verification_email(
            "alice@example.com",
            "https://auth.example/verify\r\nX-Injected: yes",
        );
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
        assert_eq!(stub.messages().len(), 0);
    }

    #[test]
    fn smtp_sender_rejects_malformed_recipient() {
        let stub = StubTransport::new_ok();
        let sender = stub_sender(stub.clone());

        let result = sender
            .send_verification_email("not-an-email-address", "https://auth.example/verify?t=abc");
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
        assert_eq!(stub.messages().len(), 0);
    }

    #[test]
    fn smtp_sender_surfaces_transport_error_without_leaking_credentials() {
        let stub = StubTransport::new_error();
        let sender = stub_sender(stub);

        let err = sender
            .send_verification_email("alice@example.com", "https://auth.example/verify?t=abc")
            .expect_err("stub error should propagate");

        match err {
            EmailError::Transport { reason } => {
                // Sanitization guard: reason should never contain secrets
                // that might show up in logs. Password fields are local to
                // the sender; they must not appear in error surfaces.
                assert!(
                    !reason.to_lowercase().contains("password"),
                    "transport error reason must not mention 'password': {reason}"
                );
            }
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[test]
    fn smtp_sender_is_object_safe_and_sendable() {
        fn assert_object_safe(_: &dyn EmailSender) {}
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let sender = stub_sender(StubTransport::new_ok());
        assert_object_safe(&sender);
        assert_send_sync(&sender);
    }

    #[test]
    fn smtp_sender_from_config_requires_smtp_block() {
        let cfg = EmailConfig {
            transport: crate::config::EmailTransport::Smtp,
            from: Some("auth@example.com".to_string()),
            smtp: None,
        };
        let err = smtp_sender_from_config(&cfg).expect_err("missing smtp block should error");
        assert!(matches!(err, EmailError::InvalidInput { .. }));
    }

    #[test]
    fn smtp_sender_from_config_builds_with_credentials() {
        let cfg = EmailConfig {
            transport: crate::config::EmailTransport::Smtp,
            from: Some("auth@example.com".to_string()),
            smtp: Some(crate::config::SmtpConfig {
                host: "mailpit".to_string(),
                port: 1025,
                encryption: SmtpEncryption::None,
                username: Some("u".to_string()),
                password: Some("p".to_string()),
            }),
        };
        let sender = smtp_sender_from_config(&cfg).expect("valid config should build");
        // Smoke test: ensure the resulting sender implements EmailSender
        // and reports a reasonable Debug representation.
        let debug = format!("{sender:?}");
        assert!(debug.contains("auth@example.com"), "debug: {debug}");
    }
}
