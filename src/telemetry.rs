//! OpenTelemetry distributed tracing initialization.
//!
//! Builds the global `tracing` subscriber, optionally layering an OTLP span
//! exporter when `observability.otlp` is configured. When the section is
//! absent the existing logging-only subscriber is installed with no OTel
//! overhead.
//!
//! # Lifecycle
//!
//! Call [`init`] once at startup and hold the returned [`TracingGuard`] for
//! the entire process lifetime. Dropping the guard flushes the batch exporter
//! and shuts down the OTel pipeline cleanly.

use opentelemetry::KeyValue;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::{ObservabilityConfig, OtlpConfig, OtlpProtocol};

/// Holds the live OTel tracer provider. Dropping this guard flushes all
/// pending spans and shuts down the export pipeline.
pub struct TracingGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

/// Initialize the global `tracing` subscriber.
///
/// When `config.otlp` is `Some`, a `BatchSpanProcessor` is wired in and
/// spans flow to the configured OTLP collector via gRPC or HTTP. When it is
/// `None`, only the fmt layer is installed (identical to the previous setup).
///
/// # Panics
///
/// Panics if the global subscriber has already been set (called twice).
pub fn init(config: &ObservabilityConfig) -> TracingGuard {
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    let json = config.log_format == "json";

    // Build the OTel layer and provider only when configured.
    if let Some(otlp_cfg) = &config.otlp {
        let provider = build_provider(otlp_cfg);
        let tracer = {
            use opentelemetry::trace::TracerProvider as _;
            provider.tracer("hearth")
        };
        opentelemetry::global::set_tracer_provider(provider.clone());
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        if json {
            tracing_subscriber::registry()
                .with(filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }

        TracingGuard {
            provider: Some(provider),
        }
    } else {
        if json {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }

        TracingGuard { provider: None }
    }
}

// ── private helpers ──────────────────────────────────────────────────────────

fn build_provider(cfg: &OtlpConfig) -> SdkTracerProvider {
    let resource = Resource::builder()
        .with_attribute(KeyValue::new(SERVICE_NAME, cfg.service_name.clone()))
        .build();
    let exporter = build_exporter(cfg);
    let processor = BatchSpanProcessor::builder(exporter).build();
    SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_resource(resource)
        .build()
}

fn build_exporter(cfg: &OtlpConfig) -> opentelemetry_otlp::SpanExporter {
    let endpoint = cfg.effective_endpoint();

    match cfg.protocol {
        OtlpProtocol::Grpc => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint);

            if !cfg.headers.is_empty() {
                let metadata = tonic_metadata_from_headers(&cfg.headers);
                builder = builder.with_metadata(metadata);
            }

            builder
                .build()
                .unwrap_or_else(|e| panic!("failed to build OTLP gRPC span exporter: {e}"))
        }
        OtlpProtocol::Http => {
            let mut builder = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(endpoint);

            if !cfg.headers.is_empty() {
                builder = builder.with_headers(cfg.headers.clone());
            }

            builder
                .build()
                .unwrap_or_else(|e| panic!("failed to build OTLP HTTP span exporter: {e}"))
        }
    }
}

fn tonic_metadata_from_headers(
    headers: &std::collections::HashMap<String, String>,
) -> tonic::metadata::MetadataMap {
    let mut map = tonic::metadata::MetadataMap::new();
    for (k, v) in headers {
        if let (Ok(key), Ok(val)) = (
            tonic::metadata::MetadataKey::from_bytes(k.as_bytes()),
            tonic::metadata::AsciiMetadataValue::try_from(v.as_str()),
        ) {
            map.insert(key, val);
        }
    }
    map
}
