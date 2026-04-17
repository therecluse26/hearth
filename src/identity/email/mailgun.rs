//! `Mailgun` email adapter.
//!
//! Delivers email via the `Mailgun` API:
//! `POST https://api.mailgun.net/v3/<domain>/messages`
//!
//! Supports EU region via <https://api.eu.mailgun.net>.

use base64::Engine;

use super::http::{HttpRequest, HttpTransport};
use super::{reject_crlf, ApiKey, EmailError, EmailMessage, EmailSender};

/// `Mailgun` API base URL (US region).
const MAILGUN_US_BASE: &str = "https://api.mailgun.net";

/// `Mailgun` API base URL (EU region).
const MAILGUN_EU_BASE: &str = "https://api.eu.mailgun.net";

/// `Mailgun` region selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MailgunRegion {
    /// US region (default).
    #[default]
    Us,
    /// EU region.
    Eu,
}

/// An [`EmailSender`] that delivers via the `Mailgun` API.
///
/// Generic over [`HttpTransport`] for testability.
pub struct MailgunEmailSender<H: HttpTransport> {
    transport: H,
    api_key: ApiKey,
    domain: String,
    from: String,
    region: MailgunRegion,
}

impl<H: HttpTransport> MailgunEmailSender<H> {
    /// Creates a new `Mailgun` sender.
    pub fn new(
        transport: H,
        api_key: ApiKey,
        domain: String,
        from: String,
        region: MailgunRegion,
    ) -> Self {
        Self {
            transport,
            api_key,
            domain,
            from,
            region,
        }
    }

    /// Returns the API URL for this sender's region and domain.
    fn api_url(&self) -> String {
        let base = match self.region {
            MailgunRegion::Us => MAILGUN_US_BASE,
            MailgunRegion::Eu => MAILGUN_EU_BASE,
        };
        format!("{base}/v3/{}/messages", self.domain)
    }
}

impl<H: HttpTransport> std::fmt::Debug for MailgunEmailSender<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailgunEmailSender")
            .field("domain", &self.domain)
            .field("from", &self.from)
            .field("region", &self.region)
            .field("api_key", &self.api_key)
            .finish_non_exhaustive()
    }
}

impl<H: HttpTransport> EmailSender for MailgunEmailSender<H> {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        reject_crlf("recipient", &message.to)?;

        // Mailgun uses form-encoded body
        let form_body = form_encode(&[
            ("from", &self.from),
            ("to", &message.to),
            ("subject", &message.subject),
            ("text", &message.text_body),
            ("html", &message.html_body),
        ]);

        // Mailgun uses HTTP Basic auth: "api:<key>"
        let credentials = format!("api:{}", self.api_key.expose_secret());
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());

        let request = HttpRequest {
            url: self.api_url(),
            headers: vec![("Authorization".to_string(), format!("Basic {encoded}"))],
            body: form_body.into_bytes(),
            content_type: "application/x-www-form-urlencoded".to_string(),
        };

        let response = self.transport.post(&request)?;

        if response.status >= 400 {
            return Err(EmailError::Transport {
                reason: format!(
                    "Mailgun API returned HTTP {}: {}",
                    response.status,
                    truncate_body(&response.body)
                ),
            });
        }

        tracing::info!(
            recipient = %message.to,
            subject = %message.subject,
            "email.send: delivered via Mailgun"
        );
        Ok(())
    }
}

/// Simple URL form encoding for key-value pairs.
fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encodes a string for use in URL form encoding.
fn url_encode(s: &str) -> String {
    use std::fmt::Write;

    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push('+'),
            _ => {
                result.push('%');
                let _ = write!(result, "{byte:02X}");
            }
        }
    }
    result
}

/// Truncates a response body for error messages.
fn truncate_body(body: &str) -> &str {
    if body.len() > 200 {
        &body[..200]
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::email::http::StubHttpTransport;

    fn test_sender(
        stub: StubHttpTransport,
        region: MailgunRegion,
    ) -> MailgunEmailSender<StubHttpTransport> {
        MailgunEmailSender::new(
            stub,
            ApiKey::new("mg-api-key-12345".to_string()),
            "mg.example.com".to_string(),
            "auth@example.com".to_string(),
            region,
        )
    }

    fn test_message() -> EmailMessage {
        EmailMessage {
            to: "alice@example.com".to_string(),
            subject: "Verify your account".to_string(),
            text_body: "Click here".to_string(),
            html_body: "<p>Click here</p>".to_string(),
        }
    }

    #[test]
    fn sends_correct_form_encoded_body() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub, MailgunRegion::Us);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url,
            "https://api.mailgun.net/v3/mg.example.com/messages"
        );
        assert_eq!(
            requests[0].content_type,
            "application/x-www-form-urlencoded"
        );

        let body = String::from_utf8(requests[0].body.clone()).expect("valid UTF-8");
        assert!(body.contains("from=auth%40example.com"), "body: {body}");
        assert!(body.contains("to=alice%40example.com"), "body: {body}");
        assert!(body.contains("subject=Verify+your+account"), "body: {body}");
    }

    #[test]
    fn sends_basic_auth_header() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub, MailgunRegion::Us);
        sender.send(&test_message()).expect("send");

        let requests = sender.transport.requests();
        let auth = requests[0]
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .expect("auth header present");
        assert!(auth.1.starts_with("Basic "), "got: {}", auth.1);

        // Decode and verify
        let encoded = auth.1.strip_prefix("Basic ").expect("prefix");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("valid base64");
        let creds = String::from_utf8(decoded).expect("valid UTF-8");
        assert_eq!(creds, "api:mg-api-key-12345");
    }

    #[test]
    fn eu_region_uses_correct_base_url() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub, MailgunRegion::Eu);
        sender.send(&test_message()).expect("send");

        let requests = sender.transport.requests();
        assert_eq!(
            requests[0].url,
            "https://api.eu.mailgun.net/v3/mg.example.com/messages"
        );
    }

    #[test]
    fn maps_non_2xx_to_error() {
        let stub = StubHttpTransport::error(400, "bad request");
        let sender = test_sender(stub, MailgunRegion::Us);
        let err = sender.send(&test_message()).expect_err("should fail");

        match err {
            EmailError::Transport { reason } => {
                assert!(reason.contains("400"), "got: {reason}");
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_api_key() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub, MailgunRegion::Us);
        let debug = format!("{sender:?}");
        assert!(!debug.contains("mg-api-key"), "debug: {debug}");
    }

    #[test]
    fn url_encode_special_characters() {
        assert_eq!(url_encode("hello world"), "hello+world");
        assert_eq!(url_encode("a@b.com"), "a%40b.com");
        assert_eq!(url_encode("key=value"), "key%3Dvalue");
    }
}
