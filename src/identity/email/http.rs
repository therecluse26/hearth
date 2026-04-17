//! Injectable HTTP transport for email provider adapters.
//!
//! Production code uses [`UreqTransport`] which wraps `ureq` with
//! `block_in_place` for multi-thread Tokio runtimes. Tests use
//! [`StubHttpTransport`] to record requests for assertions.

use std::sync::Mutex;

use super::EmailError;

/// An HTTP request to be sent by the transport.
pub struct HttpRequest {
    /// Target URL.
    pub url: String,
    /// HTTP headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
    /// Content-Type header value for the body.
    pub content_type: String,
}

/// An HTTP response from the transport.
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body as a string.
    pub body: String,
}

/// Trait for injectable HTTP transports.
///
/// Provider adapters are generic over this trait so tests can swap in
/// [`StubHttpTransport`] without touching the network.
pub trait HttpTransport: Send + Sync {
    /// Sends an HTTP POST request and returns the response.
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, EmailError>;
}

/// Production HTTP transport using `ureq`.
///
/// Wraps blocking I/O in `block_in_place` when a multi-thread Tokio
/// runtime is detected (same pattern as SMTP sender).
pub struct UreqTransport;

impl HttpTransport for UreqTransport {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, EmailError> {
        let do_request = || {
            let mut req = ureq::post(&request.url).header("Content-Type", &request.content_type);

            for (name, value) in &request.headers {
                req = req.header(name.as_str(), value.as_str());
            }

            let response = req.send(&request.body).map_err(|e| EmailError::Transport {
                reason: format!("HTTP request failed: {e}"),
            })?;

            let status: u16 = response.status().into();
            let body =
                response
                    .into_body()
                    .read_to_string()
                    .map_err(|e| EmailError::Transport {
                        reason: format!("failed to read response body: {e}"),
                    })?;

            Ok(HttpResponse { status, body })
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(do_request)
            }
            _ => do_request(),
        }
    }
}

/// A recorded HTTP request for test assertions.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// The target URL.
    pub url: String,
    /// HTTP headers.
    pub headers: Vec<(String, String)>,
    /// Request body as bytes.
    pub body: Vec<u8>,
    /// Content-Type of the request.
    pub content_type: String,
}

/// A test HTTP transport that records requests and returns canned responses.
pub struct StubHttpTransport {
    requests: Mutex<Vec<RecordedRequest>>,
    response_status: u16,
    response_body: String,
}

impl StubHttpTransport {
    /// Creates a stub that returns a successful (200) response.
    pub fn success() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response_status: 200,
            response_body: String::new(),
        }
    }

    /// Creates a stub that returns an error response.
    pub fn error(status: u16, body: &str) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            response_status: status,
            response_body: body.to_string(),
        }
    }

    /// Returns all recorded requests.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("lock").clone()
    }
}

impl HttpTransport for StubHttpTransport {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, EmailError> {
        let recorded = RecordedRequest {
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
            content_type: request.content_type.clone(),
        };
        self.requests.lock().expect("lock").push(recorded);

        Ok(HttpResponse {
            status: self.response_status,
            body: self.response_body.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_records_requests() {
        let stub = StubHttpTransport::success();
        let req = HttpRequest {
            url: "https://api.example.com/send".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer key".to_string())],
            body: b"hello".to_vec(),
            content_type: "application/json".to_string(),
        };

        let resp = stub.post(&req).expect("stub should succeed");
        assert_eq!(resp.status, 200);

        let recorded = stub.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].url, "https://api.example.com/send");
        assert_eq!(recorded[0].headers[0].0, "Authorization");
        assert_eq!(recorded[0].body, b"hello");
    }

    #[test]
    fn stub_returns_error_response() {
        let stub = StubHttpTransport::error(403, "forbidden");
        let req = HttpRequest {
            url: "https://api.example.com/send".to_string(),
            headers: vec![],
            body: vec![],
            content_type: "application/json".to_string(),
        };

        let resp = stub.post(&req).expect("stub should return response");
        assert_eq!(resp.status, 403);
        assert_eq!(resp.body, "forbidden");
    }
}
