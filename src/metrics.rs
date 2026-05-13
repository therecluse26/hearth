//! Prometheus metrics registry and metric definitions for Hearth.
//!
//! All metrics are registered into a dedicated [`Registry`] (not the
//! process-global default) so the namespace is clean and the registry can
//! be exercised in unit tests without global state pollution.
//!
//! # Usage
//!
//! Increment counters and observe histograms directly on [`METRICS`]:
//!
//! ```no_run
//! # use hearth::metrics::METRICS;
//! METRICS.tokens_issued_total
//!     .with_label_values(&["my-realm", "authorization_code"])
//!     .inc();
//! ```
//!
//! Render the current snapshot for the `/metrics` scrape endpoint via
//! [`Metrics::render`].

use std::sync::OnceLock;

use prometheus::{CounterVec, Gauge, HistogramOpts, HistogramVec, Opts, Registry};

/// HTTP request latency histogram buckets (seconds).
///
/// Range: 1 ms → 2.5 s, covering sub-millisecond hot-path responses
/// through the occasional slow admin or federation request.
const HTTP_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5];

/// Storage operation latency histogram buckets (seconds).
///
/// Range: 50 µs → 100 ms, covering WAL flush and SST scan latencies.
/// Does not apply to hot-tier reads, which bypass storage instrumentation
/// to avoid syscall overhead on the hot path.
const STORAGE_BUCKETS: &[f64] =
    &[0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1];

/// All Prometheus metrics collected by the Hearth server.
///
/// Obtain the process-global singleton via [`METRICS`].
pub struct Metrics {
    /// Prometheus registry backing all metrics in this struct.
    ///
    /// Exposed so the `/metrics` handler can call
    /// `registry.gather()` without another layer of indirection.
    registry: Registry,

    /// HTTP request latency histogram in seconds.
    ///
    /// Labels: `method` (HTTP verb), `route` (matched path pattern),
    /// `status` (HTTP status code as string).
    pub http_request_duration_seconds: HistogramVec,

    /// Total authentication attempts, by outcome.
    ///
    /// Labels: `realm` (realm UUID string), `outcome` (`success` | `failure`).
    pub auth_attempts_total: CounterVec,

    /// Total tokens issued, by grant type.
    ///
    /// Labels: `realm` (realm UUID string), `grant_type`
    /// (`authorization_code` | `refresh_token` | `client_credentials` |
    /// `urn:ietf:params:oauth:grant-type:device_code`).
    pub tokens_issued_total: CounterVec,

    /// Instantaneous count of active sessions across all realms.
    ///
    /// Incremented on `create_session`; decremented on `revoke_session`.
    pub active_sessions: Gauge,

    /// Storage write and scan operation latency in seconds.
    ///
    /// Labels: `operation` (`put` | `delete` | `put_batch` | `scan`).
    /// `get` is intentionally excluded — hot-tier reads bypass this layer
    /// and adding `Instant::now()` to every `get` would violate the
    /// zero-syscall hot-path contract.
    pub storage_operation_duration_seconds: HistogramVec,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();

        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "hearth_http_request_duration_seconds",
                "HTTP request latency in seconds",
            )
            .buckets(HTTP_BUCKETS.to_vec()),
            &["method", "route", "status"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let auth_attempts_total = CounterVec::new(
            Opts::new(
                "hearth_auth_attempts_total",
                "Total authentication attempts, labelled by outcome",
            ),
            &["realm", "outcome"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(auth_attempts_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let tokens_issued_total = CounterVec::new(
            Opts::new(
                "hearth_tokens_issued_total",
                "Total tokens issued, labelled by grant type",
            ),
            &["realm", "grant_type"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(tokens_issued_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let active_sessions = Gauge::new(
            "hearth_active_sessions",
            "Instantaneous count of active sessions across all realms",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(active_sessions.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_operation_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "hearth_storage_operation_duration_seconds",
                "Storage write and scan operation latency in seconds",
            )
            .buckets(STORAGE_BUCKETS.to_vec()),
            &["operation"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_operation_duration_seconds.clone()))
            .expect("metric registration succeeds on a fresh registry");

        Self {
            registry,
            http_request_duration_seconds,
            auth_attempts_total,
            tokens_issued_total,
            active_sessions,
            storage_operation_duration_seconds,
        }
    }

    /// Renders all collected metrics in Prometheus text exposition format.
    ///
    /// The returned string is ready to serve verbatim from the `/metrics`
    /// endpoint with `Content-Type: text/plain; version=0.0.4`.
    pub fn render(&self) -> String {
        use prometheus::Encoder as _;
        let encoder = prometheus::TextEncoder::new();
        let families = self.registry.gather();
        let mut buf = Vec::new();
        if let Err(e) = encoder.encode(&families, &mut buf) {
            tracing::error!(error = %e, "failed to encode Prometheus metrics");
            return String::new();
        }
        // Prometheus text format is always valid UTF-8.
        String::from_utf8(buf).unwrap_or_default()
    }
}

/// Process-global [`Metrics`] singleton backing storage.
static INSTANCE: OnceLock<Metrics> = OnceLock::new();

/// Returns the process-global [`Metrics`] singleton, initialising it on first call.
///
/// Uses [`OnceLock`] (not `lazy_static!`) per the project policy.
pub fn metrics() -> &'static Metrics {
    INSTANCE.get_or_init(Metrics::new)
}
