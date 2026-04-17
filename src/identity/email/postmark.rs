//! `Postmark` email adapter.
//!
//! Delivers email via the `Postmark` API:
//! `POST https://api.postmarkapp.com/email`

use super::http::{HttpRequest, HttpTransport};
use super::{reject_crlf, ApiKey, EmailError, EmailMessage, EmailSender};

/// `Postmark` API base URL.
const POSTMARK_API_URL: &str = "https://api.postmarkapp.com/email";

/// An [`EmailSender`] that delivers via the `Postmark` API.
///
/// Generic over [`HttpTransport`] for testability.
pub struct PostmarkEmailSender<H: HttpTransport> {
    transport: H,
    server_token: ApiKey,
    from: String,
}

impl<H: HttpTransport> PostmarkEmailSender<H> {
    /// Creates a new `Postmark` sender.
    pub fn new(transport: H, server_token: ApiKey, from: String) -> Self {
        Self {
            transport,
            server_token,
            from,
        }
    }
}

impl<H: HttpTransport> std::fmt::Debug for PostmarkEmailSender<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostmarkEmailSender")
            .field("from", &self.from)
            .field("server_token", &self.server_token)
            .finish_non_exhaustive()
    }
}

impl<H: HttpTransport> EmailSender for PostmarkEmailSender<H> {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        reject_crlf("recipient", &message.to)?;

        let payload = serde_json::json!({
            "From": self.from,
            "To": message.to,
            "Subject": message.subject,
            "TextBody": message.text_body,
            "HtmlBody": message.html_body,
        });

        let body = serde_json::to_vec(&payload).map_err(|e| EmailError::InvalidInput {
            reason: format!("failed to serialize Postmark payload: {e}"),
        })?;

        let request = HttpRequest {
            url: POSTMARK_API_URL.to_string(),
            headers: vec![
                ("Accept".to_string(), "application/json".to_string()),
                (
                    "X-Postmark-Server-Token".to_string(),
                    self.server_token.expose_secret().to_string(),
                ),
            ],
            body,
            content_type: "application/json".to_string(),
        };

        let response = self.transport.post(&request)?;

        if response.status >= 400 {
            return Err(EmailError::Transport {
                reason: format!(
                    "Postmark API returned HTTP {}: {}",
                    response.status,
                    truncate_body(&response.body)
                ),
            });
        }

        tracing::info!(
            recipient = %message.to,
            subject = %message.subject,
            "email.send: delivered via Postmark"
        );
        Ok(())
    }
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

    fn test_sender(stub: StubHttpTransport) -> PostmarkEmailSender<StubHttpTransport> {
        PostmarkEmailSender::new(
            stub,
            ApiKey::new("pm-server-token-12345".to_string()),
            "auth@example.com".to_string(),
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
    fn sends_correct_json_payload() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, POSTMARK_API_URL);

        let payload: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(payload["From"], "auth@example.com");
        assert_eq!(payload["To"], "alice@example.com");
        assert_eq!(payload["Subject"], "Verify your account");
        assert_eq!(payload["TextBody"], "Click here");
        assert_eq!(payload["HtmlBody"], "<p>Click here</p>");
    }

    #[test]
    fn sends_server_token_header() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send");

        let requests = sender.transport.requests();
        let token_header = requests[0]
            .headers
            .iter()
            .find(|(k, _)| k == "X-Postmark-Server-Token")
            .expect("token header present");
        assert_eq!(token_header.1, "pm-server-token-12345");
    }

    #[test]
    fn maps_non_2xx_to_error() {
        let stub = StubHttpTransport::error(422, "invalid");
        let sender = test_sender(stub);
        let err = sender.send(&test_message()).expect_err("should fail");

        match err {
            EmailError::Transport { reason } => {
                assert!(reason.contains("422"), "got: {reason}");
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_token() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub);
        let debug = format!("{sender:?}");
        assert!(!debug.contains("pm-server-token"), "debug: {debug}");
    }
}
