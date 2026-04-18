//! `Mailtrap` email adapter.
//!
//! Delivers email via the `Mailtrap` Sending API or Sandbox API:
//! - Sending: `POST https://send.api.mailtrap.io/api/send`
//! - Sandbox: `POST https://sandbox.api.mailtrap.io/api/send/{inbox_id}`

use super::http::{HttpRequest, HttpTransport};
use super::{reject_crlf, ApiKey, EmailError, EmailMessage, EmailSender};

/// `Mailtrap` Sending API base URL (production).
const MAILTRAP_SENDING_URL: &str = "https://send.api.mailtrap.io/api/send";

/// `Mailtrap` Sandbox API base URL (testing).
const MAILTRAP_SANDBOX_URL: &str = "https://sandbox.api.mailtrap.io/api/send";

/// An [`EmailSender`] that delivers via the `Mailtrap` Sending or Sandbox API.
///
/// When `inbox_id` is `Some`, the sandbox endpoint is used (for development
/// and testing with an account-level API token). When `None`, the production
/// sending endpoint is used (requires a domain-verified sending token).
///
/// Generic over [`HttpTransport`] for testability.
pub struct MailtrapEmailSender<H: HttpTransport> {
    transport: H,
    api_key: ApiKey,
    from: String,
    inbox_id: Option<u64>,
}

impl<H: HttpTransport> MailtrapEmailSender<H> {
    /// Creates a new `Mailtrap` sender.
    ///
    /// Pass `inbox_id: Some(id)` to target the sandbox API, or `None` for the
    /// production sending API.
    pub fn new(transport: H, api_key: ApiKey, from: String, inbox_id: Option<u64>) -> Self {
        Self {
            transport,
            api_key,
            from,
            inbox_id,
        }
    }

    /// Returns the API URL based on the configured mode.
    fn api_url(&self) -> String {
        match self.inbox_id {
            Some(id) => format!("{MAILTRAP_SANDBOX_URL}/{id}"),
            None => MAILTRAP_SENDING_URL.to_string(),
        }
    }
}

impl<H: HttpTransport> std::fmt::Debug for MailtrapEmailSender<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailtrapEmailSender")
            .field("from", &self.from)
            .field("api_key", &self.api_key)
            .field("mode", &if self.inbox_id.is_some() { "sandbox" } else { "sending" })
            .finish_non_exhaustive()
    }
}

impl<H: HttpTransport> EmailSender for MailtrapEmailSender<H> {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        reject_crlf("recipient", &message.to)?;

        let payload = serde_json::json!({
            "from": { "email": self.from },
            "to": [{ "email": message.to }],
            "subject": message.subject,
            "text": message.text_body,
            "html": message.html_body,
        });

        let body = serde_json::to_vec(&payload).map_err(|e| EmailError::InvalidInput {
            reason: format!("failed to serialize Mailtrap payload: {e}"),
        })?;

        let request = HttpRequest {
            url: self.api_url(),
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer {}", self.api_key.expose_secret()),
            )],
            body,
            content_type: "application/json".to_string(),
        };

        let response = self.transport.post(&request)?;

        if response.status >= 400 {
            return Err(EmailError::Transport {
                reason: format!(
                    "Mailtrap API returned HTTP {}: {}",
                    response.status,
                    truncate_body(&response.body)
                ),
            });
        }

        tracing::info!(
            recipient = %message.to,
            subject = %message.subject,
            "email.send: delivered via Mailtrap"
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

    fn test_sender(stub: StubHttpTransport) -> MailtrapEmailSender<StubHttpTransport> {
        MailtrapEmailSender::new(
            stub,
            ApiKey::new("mt-test-api-key".to_string()),
            "auth@example.com".to_string(),
            None,
        )
    }

    fn test_sandbox_sender(stub: StubHttpTransport) -> MailtrapEmailSender<StubHttpTransport> {
        MailtrapEmailSender::new(
            stub,
            ApiKey::new("mt-test-api-key".to_string()),
            "auth@example.com".to_string(),
            Some(12345),
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
        assert_eq!(requests[0].url, MAILTRAP_SENDING_URL);
        assert_eq!(requests[0].content_type, "application/json");

        let payload: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(payload["from"]["email"], "auth@example.com");
        assert_eq!(payload["to"][0]["email"], "alice@example.com");
        assert_eq!(payload["subject"], "Verify your account");
        assert_eq!(payload["text"], "Click here");
        assert_eq!(payload["html"], "<p>Click here</p>");
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
        assert_eq!(auth.1, "Bearer mt-test-api-key");
    }

    #[test]
    fn maps_non_2xx_to_error() {
        let stub = StubHttpTransport::error(401, "unauthorized");
        let sender = test_sender(stub);
        let err = sender.send(&test_message()).expect_err("should fail");

        match err {
            EmailError::Transport { reason } => {
                assert!(reason.contains("401"), "got: {reason}");
                assert!(reason.contains("unauthorized"), "got: {reason}");
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_api_key() {
        let stub = StubHttpTransport::success();
        let sender = test_sender(stub);
        let debug = format!("{sender:?}");
        assert!(!debug.contains("mt-test-api-key"), "debug: {debug}");
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

    #[test]
    fn sandbox_mode_uses_inbox_url() {
        let stub = StubHttpTransport::success();
        let sender = test_sandbox_sender(stub);
        sender.send(&test_message()).expect("send should succeed");

        let requests = sender.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url,
            "https://sandbox.api.mailtrap.io/api/send/12345"
        );
    }

    #[test]
    fn sandbox_mode_sends_same_auth_and_payload() {
        let stub = StubHttpTransport::success();
        let sender = test_sandbox_sender(stub);
        sender.send(&test_message()).expect("send");

        let requests = sender.transport.requests();
        let auth = requests[0]
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .expect("auth header present");
        assert_eq!(auth.1, "Bearer mt-test-api-key");

        let payload: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(payload["from"]["email"], "auth@example.com");
        assert_eq!(payload["to"][0]["email"], "alice@example.com");
    }

    #[test]
    fn debug_shows_mode() {
        let stub_send = StubHttpTransport::success();
        let sender = test_sender(stub_send);
        let debug = format!("{sender:?}");
        assert!(debug.contains("\"sending\""), "debug: {debug}");

        let stub_sandbox = StubHttpTransport::success();
        let sandbox = test_sandbox_sender(stub_sandbox);
        let debug = format!("{sandbox:?}");
        assert!(debug.contains("\"sandbox\""), "debug: {debug}");
    }
}
