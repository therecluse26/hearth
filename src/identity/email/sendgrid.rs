//! `SendGrid` email adapter.
//!
//! Delivers email via the `SendGrid` v3 API:
//! `POST https://api.sendgrid.com/v3/mail/send`

use super::http::{HttpRequest, HttpTransport};
use super::{reject_crlf, ApiKey, EmailError, EmailMessage, EmailSender};

/// `SendGrid` API base URL.
const SENDGRID_API_URL: &str = "https://api.sendgrid.com/v3/mail/send";

/// An [`EmailSender`] that delivers via the `SendGrid` v3 API.
///
/// Generic over [`HttpTransport`] for testability.
pub struct SendgridEmailSender<H: HttpTransport> {
    transport: H,
    api_key: ApiKey,
    from: String,
}

impl<H: HttpTransport> SendgridEmailSender<H> {
    /// Creates a new `SendGrid` sender.
    pub fn new(transport: H, api_key: ApiKey, from: String) -> Self {
        Self {
            transport,
            api_key,
            from,
        }
    }
}

impl<H: HttpTransport> std::fmt::Debug for SendgridEmailSender<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendgridEmailSender")
            .field("from", &self.from)
            .field("api_key", &self.api_key)
            .finish_non_exhaustive()
    }
}

impl<H: HttpTransport> EmailSender for SendgridEmailSender<H> {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        reject_crlf("recipient", &message.to)?;

        let payload = serde_json::json!({
            "personalizations": [{
                "to": [{ "email": message.to }]
            }],
            "from": { "email": self.from },
            "subject": message.subject,
            "content": [
                { "type": "text/plain", "value": message.text_body },
                { "type": "text/html", "value": message.html_body }
            ]
        });

        let body = serde_json::to_vec(&payload).map_err(|e| EmailError::InvalidInput {
            reason: format!("failed to serialize SendGrid payload: {e}"),
        })?;

        let request = HttpRequest {
            url: SENDGRID_API_URL.to_string(),
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer {}", self.api_key.expose_secret()),
            )],
            body,
            content_type: "application/json".to_string(),
        };

        let response = self.transport.post(&request)?;

        // SendGrid returns 202 Accepted for successful sends.
        if response.status >= 400 {
            return Err(EmailError::Transport {
                reason: format!(
                    "SendGrid API returned HTTP {}: {}",
                    response.status,
                    truncate_body(&response.body)
                ),
            });
        }

        tracing::info!(
            recipient = %message.to,
            subject = %message.subject,
            "email.send: delivered via SendGrid"
        );
        Ok(())
    }
}

/// Truncates a response body for error messages (avoids giant blobs in logs).
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

    fn test_sender(stub: StubHttpTransport) -> SendgridEmailSender<StubHttpTransport> {
        SendgridEmailSender::new(
            stub,
            ApiKey::new("SG.test-api-key".to_string()),
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
        assert_eq!(requests[0].url, SENDGRID_API_URL);
        assert_eq!(requests[0].content_type, "application/json");

        let payload: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(
            payload["personalizations"][0]["to"][0]["email"],
            "alice@example.com"
        );
        assert_eq!(payload["from"]["email"], "auth@example.com");
        assert_eq!(payload["subject"], "Verify your account");
        assert_eq!(payload["content"][0]["type"], "text/plain");
        assert_eq!(payload["content"][1]["type"], "text/html");
    }

    #[test]
    fn sends_bearer_auth_header() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub);
        sender.send(&test_message()).expect("send");

        let requests = sender.transport.requests();
        let auth = requests[0]
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .expect("auth header present");
        assert_eq!(auth.1, "Bearer SG.test-api-key");
    }

    #[test]
    fn maps_non_2xx_to_error() {
        let stub = StubHttpTransport::error(403, "forbidden");
        let sender = test_sender(stub);
        let err = sender.send(&test_message()).expect_err("should fail");

        match err {
            EmailError::Transport { reason } => {
                assert!(reason.contains("403"), "got: {reason}");
                assert!(reason.contains("forbidden"), "got: {reason}");
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_api_key() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub);
        let debug = format!("{sender:?}");
        assert!(!debug.contains("SG.test-api-key"), "debug: {debug}");
        assert!(debug.contains("ApiKey(***)"), "debug: {debug}");
    }

    #[test]
    fn rejects_crlf_in_recipient() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub);
        let mut msg = test_message();
        msg.to = "bad@x.com\r\nBcc: evil@x.com".to_string();
        let result = sender.send(&msg);
        assert!(matches!(result, Err(EmailError::InvalidInput { .. })));
    }
}
