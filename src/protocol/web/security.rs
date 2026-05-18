//! Tower middleware that appends security response headers to every UI response.
//!
//! Headers applied:
//! - `Content-Security-Policy` — restricts script/style/connect sources.
//! - `X-Frame-Options: DENY` — prevents clickjacking.
//! - `X-Content-Type-Options: nosniff` — blocks MIME-type sniffing.
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `Strict-Transport-Security` — only when TLS is enabled.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{HeaderName, HeaderValue, Request, Response};
use tower::{Layer, Service};

/// Settings that control which optional headers are emitted.
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    /// Emit HSTS header (only set when the server is serving TLS).
    pub hsts_enabled: bool,
}

/// Tower layer that wraps services with security header injection.
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    config: Arc<SecurityConfig>,
}

impl SecurityHeadersLayer {
    /// Creates a new layer. Set `hsts_enabled` to `true` when TLS is active.
    #[must_use]
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// Tower service produced by [`SecurityHeadersLayer`].
#[derive(Clone)]
pub struct SecurityHeadersService<S> {
    inner: S,
    config: Arc<SecurityConfig>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    ReqBody: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let hsts_enabled = self.config.hsts_enabled;
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut resp = fut.await?;
            let headers = resp.headers_mut();
            insert(headers, "x-frame-options", "DENY");
            insert(headers, "x-content-type-options", "nosniff");
            insert(
                headers,
                "referrer-policy",
                "strict-origin-when-cross-origin",
            );
            // Alpine.js v3 uses new Function() for expression evaluation,
            // which requires 'unsafe-eval'. No inline scripts remain after
            // extracting them to layout.js, so 'unsafe-inline' is omitted.
            insert(
                headers,
                "content-security-policy",
                "default-src 'self'; \
                 script-src 'self' 'unsafe-eval' cdn.jsdelivr.net; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:; \
                 connect-src 'self'; \
                 font-src 'self'; \
                 frame-ancestors 'none'",
            );
            if hsts_enabled {
                insert(
                    headers,
                    "strict-transport-security",
                    "max-age=31536000; includeSubDomains",
                );
            }
            Ok(resp)
        })
    }
}

fn insert(headers: &mut axum::http::HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use tower::ServiceExt;

    use super::*;

    async fn ok_handler(_req: Request<Body>) -> Result<axum::response::Response, Infallible> {
        Ok(StatusCode::OK.into_response())
    }

    #[tokio::test]
    async fn security_headers_present() {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
        });
        let svc = layer.layer(tower::service_fn(ok_handler));
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("service call");

        let headers = resp.headers();
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert!(headers.contains_key("content-security-policy"));
        assert!(!headers.contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn hsts_emitted_when_tls_enabled() {
        let layer = SecurityHeadersLayer::new(SecurityConfig { hsts_enabled: true });
        let svc = layer.layer(tower::service_fn(ok_handler));
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("service call");

        assert!(resp.headers().contains_key("strict-transport-security"));
    }
}
