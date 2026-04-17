//! SMTP email sender — delivers messages via an external mail server.
//!
//! Generic over the underlying `lettre::Transport` so tests can drive
//! the sender with `lettre::transport::stub::StubTransport`, bypassing
//! any network I/O. Production code uses [`smtp_sender_from_config`]
//! which pins `T = SmtpTransport`.

use std::fmt;

use lettre::{
    message::{header::ContentType, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::{authentication::Credentials, SmtpTransport},
    Transport,
};

use crate::config::{EmailConfig, SmtpEncryption};

use super::{reject_crlf, EmailError, EmailMessage, EmailSender};

/// An [`EmailSender`] that delivers messages via SMTP.
///
/// Generic over the underlying `lettre::Transport` so tests can drive
/// the sender with `lettre::transport::stub::StubTransport`, bypassing
/// any network I/O.
///
/// # Blocking behavior
///
/// `lettre::SmtpTransport::send` is a blocking call. Because [`EmailSender`]
/// is a sync trait called from async handlers, `send` guards the underlying
/// transport with `tokio::task::block_in_place` when a multi-threaded Tokio
/// runtime is detected. On current-thread runtimes the send runs directly.
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
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        reject_crlf("recipient", &message.to)?;
        reject_crlf("subject", &message.subject)?;

        let to_mailbox: Mailbox =
            message
                .to
                .parse()
                .map_err(
                    |e: lettre::address::AddressError| EmailError::InvalidInput {
                        reason: format!("recipient: {e}"),
                    },
                )?;

        let msg = Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
            .subject(&message.subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(message.text_body.clone()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(message.html_body.clone()),
                    ),
            )
            .map_err(|e| EmailError::InvalidInput {
                reason: e.to_string(),
            })?;

        // Sync `send` on lettre's SmtpTransport is blocking (TCP + TLS +
        // SMTP dialogue). Guard with `block_in_place` on the multi-thread
        // runtime so we don't starve the tokio worker.
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
            recipient = %message.to,
            subject = %message.subject,
            "email.send: delivered via SMTP"
        );
        Ok(())
    }
}

/// Builds a production [`SmtpEmailSender`] from an [`EmailConfig`].
///
/// The caller is responsible for passing a config whose `transport` is
/// [`crate::config::EmailTransport::Smtp`]; validation has already
/// confirmed that `from` and `smtp` are both present and well-formed.
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

#[cfg(test)]
mod tests {
    use super::*;
    use lettre::transport::stub::StubTransport;

    fn stub_sender(stub: StubTransport) -> SmtpEmailSender<StubTransport> {
        let from: Mailbox = "Hearth <auth@example.com>"
            .parse()
            .expect("static mailbox parses");
        SmtpEmailSender::new(stub, from)
    }

    fn test_message(to: &str, subject: &str) -> EmailMessage {
        EmailMessage {
            to: to.to_string(),
            subject: subject.to_string(),
            text_body: "Click here: https://auth.example/verify?t=abc".to_string(),
            html_body: "<p>Click <a href=\"https://auth.example/verify?t=abc\">here</a></p>"
                .to_string(),
        }
    }

    #[test]
    fn smtp_sender_delivers_multipart_message() {
        let stub = StubTransport::new_ok();
        let sender = stub_sender(stub.clone());

        let msg = test_message("Alice <alice@example.com>", "Verify your account");
        sender.send(&msg).expect("send should succeed with stub");

        let messages = stub.messages();
        assert_eq!(messages.len(), 1, "exactly one message delivered");
        let (envelope, body) = &messages[0];

        assert!(
            envelope
                .from()
                .is_some_and(|f| f.to_string() == "auth@example.com"),
            "envelope from: {:?}",
            envelope.from()
        );
        let to: Vec<String> = envelope.to().iter().map(ToString::to_string).collect();
        assert_eq!(to, vec!["alice@example.com".to_string()]);

        assert!(
            body.contains("Subject: Verify your account"),
            "body: {body}"
        );
        assert!(
            body.contains("text/plain"),
            "missing text/plain part: {body}"
        );
        assert!(body.contains("text/html"), "missing text/html part: {body}");
    }

    #[test]
    fn smtp_sender_rejects_crlf_in_recipient() {
        let stub = StubTransport::new_ok();
        let sender = stub_sender(stub.clone());

        let msg = test_message("alice@example.com\r\nBcc: attacker@example.com", "Test");
        let result = sender.send(&msg);
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
        assert_eq!(stub.messages().len(), 0, "no message should be sent");
    }

    #[test]
    fn smtp_sender_rejects_crlf_in_subject() {
        let stub = StubTransport::new_ok();
        let sender = stub_sender(stub.clone());

        let msg = test_message("alice@example.com", "Subject\r\nX-Injected: yes");
        let result = sender.send(&msg);
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
        assert_eq!(stub.messages().len(), 0);
    }

    #[test]
    fn smtp_sender_rejects_malformed_recipient() {
        let stub = StubTransport::new_ok();
        let sender = stub_sender(stub.clone());

        let msg = test_message("not-an-email-address", "Test");
        let result = sender.send(&msg);
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
        assert_eq!(stub.messages().len(), 0);
    }

    #[test]
    fn smtp_sender_surfaces_transport_error() {
        let stub = StubTransport::new_error();
        let sender = stub_sender(stub);

        let msg = test_message("alice@example.com", "Test");
        let err = sender.send(&msg).expect_err("stub error should propagate");

        match err {
            EmailError::Transport { reason } => {
                assert!(
                    !reason.to_lowercase().contains("password"),
                    "transport error must not mention 'password': {reason}"
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
            ..EmailConfig::default()
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
            ..EmailConfig::default()
        };
        let sender = smtp_sender_from_config(&cfg).expect("valid config should build");
        let debug = format!("{sender:?}");
        assert!(debug.contains("auth@example.com"), "debug: {debug}");
    }
}
