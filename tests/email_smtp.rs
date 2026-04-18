//! Black-box integration tests for the SMTP email transport.
//!
//! These tests exercise the full pipeline from YAML config -> validation
//! -> construction of an `EmailSender` -> message delivery, using
//! `lettre::transport::stub::StubTransport` as the backing transport so
//! no real network I/O is performed. The goal is to catch regressions
//! where the config shape, validator, and sender wiring drift out of
//! sync with each other.
//!
//! See `src/identity/email/smtp.rs` for unit tests on the sender itself.

use hearth::config::{Config, EmailTransport, SmtpConfig, SmtpEncryption};
use hearth::identity::email::{EmailMessage, EmailSender, SmtpEmailSender};
use lettre::message::Mailbox;
use lettre::transport::stub::StubTransport;

// ===== Config validation round-trips =====

#[test]
fn smtp_config_yaml_round_trips_with_all_encryption_modes() {
    for mode in ["none", "starttls", "tls"] {
        let yaml = format!(
            r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  from: "Hearth <auth@example.com>"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: {mode}
"#
        );
        let config = Config::from_yaml_str(&yaml)
            .unwrap_or_else(|e| panic!("mode={mode} should parse: {e}"));
        assert_eq!(config.email.transport, EmailTransport::Smtp);
        let smtp = config.email.smtp.expect("smtp block present");
        let expected = match mode {
            "none" => SmtpEncryption::None,
            "starttls" => SmtpEncryption::Starttls,
            "tls" => SmtpEncryption::Tls,
            _ => unreachable!(),
        };
        assert_eq!(smtp.encryption, expected);
    }
}

#[test]
fn smtp_transport_without_smtp_block_fails_validation() {
    let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  from: "auth@example.com"
"#;
    let err = Config::from_yaml_str(yaml).expect_err("missing smtp block should fail");
    let display = format!("{err}");
    assert!(display.contains("email.smtp"), "got: {display}");
}

#[test]
fn smtp_transport_without_from_fails_validation() {
    let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  smtp:
    host: "smtp.example.com"
    port: 587
"#;
    let err = Config::from_yaml_str(yaml).expect_err("missing from should fail");
    let display = format!("{err}");
    assert!(display.contains("email.from"), "got: {display}");
}

#[test]
fn smtp_transport_with_orphaned_username_fails_validation() {
    let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  from: "auth@example.com"
  smtp:
    host: "smtp.example.com"
    port: 587
    username: "u"
"#;
    let err = Config::from_yaml_str(yaml).expect_err("orphaned username should fail");
    let display = format!("{err}");
    assert!(display.contains("email.smtp.password"), "got: {display}");
}

#[test]
fn smtp_transport_with_orphaned_password_fails_validation() {
    let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  from: "auth@example.com"
  smtp:
    host: "smtp.example.com"
    port: 587
    password: "p"
"#;
    let err = Config::from_yaml_str(yaml).expect_err("orphaned password should fail");
    let display = format!("{err}");
    assert!(display.contains("email.smtp.username"), "got: {display}");
}

#[test]
fn log_transport_accepts_minimal_config() {
    let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
"#;
    let config = Config::from_yaml_str(yaml).expect("default config should parse");
    assert_eq!(config.email.transport, EmailTransport::Log);
    assert!(config.email.smtp.is_none());
}

// ===== End-to-end delivery through StubTransport =====

fn stub_sender_from_config(config: &Config, stub: StubTransport) -> SmtpEmailSender<StubTransport> {
    assert_eq!(
        config.email.transport,
        EmailTransport::Smtp,
        "test expects SMTP transport"
    );
    let from_str = config
        .email
        .from
        .as_ref()
        .expect("validated config has from");
    let from: Mailbox = from_str.parse().expect("validated mailbox parses");
    SmtpEmailSender::new(stub, from)
}

#[test]
fn full_pipeline_delivers_verification_email() {
    let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  from: "Hearth <auth@example.com>"
  smtp:
    host: "mailpit"
    port: 1025
    encryption: none
"#;
    let config = Config::from_yaml_str(yaml).expect("valid SMTP config");

    let stub = StubTransport::new_ok();
    let sender = stub_sender_from_config(&config, stub.clone());

    let msg = EmailMessage {
        to: "alice@example.com".to_string(),
        subject: "Verify your Hearth account".to_string(),
        text_body: "Click: https://auth.example.com/ui/verify-email?token=Qx_42".to_string(),
        html_body:
            "<p>Click <a href=\"https://auth.example.com/ui/verify-email?token=Qx_42\">here</a></p>"
                .to_string(),
    };
    sender.send(&msg).expect("send should succeed through stub");

    let messages = stub.messages();
    assert_eq!(messages.len(), 1, "exactly one message");
    let (envelope, body) = &messages[0];

    assert_eq!(
        envelope.from().map(ToString::to_string),
        Some("auth@example.com".to_string()),
    );
    let recipients: Vec<String> = envelope.to().iter().map(ToString::to_string).collect();
    assert_eq!(recipients, vec!["alice@example.com".to_string()]);

    assert!(
        body.contains("Subject: Verify your Hearth account"),
        "missing subject: {body}"
    );
    assert!(
        body.contains("https://auth.example.com/ui/verify-email?token=Qx_42"),
        "missing URL: {body}"
    );
}

#[test]
fn pipeline_preserves_credentials_through_to_sender_shape() {
    let cfg = hearth::config::EmailConfig {
        transport: EmailTransport::Smtp,
        from: Some("auth@example.com".to_string()),
        smtp: Some(SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            encryption: SmtpEncryption::Starttls,
            username: Some("notifications".to_string()),
            password: Some("hunter2".to_string()),
        }),
        ..hearth::config::EmailConfig::default()
    };
    let sender = hearth::identity::email::smtp_sender_from_config(&cfg)
        .expect("credentialed SMTP config should build");
    let debug = format!("{sender:?}");
    assert!(
        !debug.contains("hunter2"),
        "Debug impl must not leak password: {debug}"
    );
}
