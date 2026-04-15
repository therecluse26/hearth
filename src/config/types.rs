//! Configuration section structs.
//!
//! Each section implements `Default` with production-safe values and
//! `Deserialize` for YAML parsing. `#[serde(default)]` on each section
//! means partial YAML files work seamlessly.

use serde::Deserialize;
use std::path::PathBuf;

/// Server network configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address to bind the server to.
    #[serde(default = "ServerConfig::default_bind_address")]
    pub bind_address: String,
    /// Port to listen on.
    #[serde(default = "ServerConfig::default_port")]
    pub port: u16,
    /// Path to TLS certificate file (optional; no TLS if absent).
    pub tls_cert_path: Option<PathBuf>,
    /// Path to TLS private key file (optional; no TLS if absent).
    pub tls_key_path: Option<PathBuf>,
    /// Path to a CA certificate for client certificate verification (mTLS).
    pub tls_client_ca_path: Option<PathBuf>,
    /// Whether to require a client certificate (mTLS). Requires `tls_client_ca_path`.
    #[serde(default)]
    pub tls_require_client_cert: bool,
}

impl ServerConfig {
    fn default_bind_address() -> String {
        "127.0.0.1".to_string()
    }

    const fn default_port() -> u16 {
        8420
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: Self::default_bind_address(),
            port: Self::default_port(),
            tls_cert_path: None,
            tls_key_path: None,
            tls_client_ca_path: None,
            tls_require_client_cert: false,
        }
    }
}

/// Storage engine configuration.
///
/// These values control WAL, memtable, and hot tier behavior.
/// Distinct from `storage::StorageConfig` — conversion happens in main.rs wiring.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageSection {
    /// Directory for data files (WAL, SSTs).
    #[serde(default = "StorageSection::default_data_dir")]
    pub data_dir: String,
    /// Maximum WAL file size in bytes before rotation.
    #[serde(default = "StorageSection::default_wal_max_size_bytes")]
    pub wal_max_size_bytes: u64,
    /// Memtable size threshold in bytes before flush to SST.
    #[serde(default = "StorageSection::default_memtable_flush_bytes")]
    pub memtable_flush_bytes: u64,
    /// Maximum number of entries in the hot tier cache.
    #[serde(default = "StorageSection::default_hot_tier_capacity")]
    pub hot_tier_capacity: usize,
    /// Whether to fsync WAL writes. MUST be true in production.
    #[serde(default = "StorageSection::default_fsync")]
    pub fsync: bool,
}

impl StorageSection {
    fn default_data_dir() -> String {
        "./data".to_string()
    }

    const fn default_wal_max_size_bytes() -> u64 {
        256 * 1024 * 1024 // 256 MiB
    }

    const fn default_memtable_flush_bytes() -> u64 {
        64 * 1024 * 1024 // 64 MiB
    }

    const fn default_hot_tier_capacity() -> usize {
        10_000
    }

    const fn default_fsync() -> bool {
        true
    }
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            data_dir: Self::default_data_dir(),
            wal_max_size_bytes: Self::default_wal_max_size_bytes(),
            memtable_flush_bytes: Self::default_memtable_flush_bytes(),
            hot_tier_capacity: Self::default_hot_tier_capacity(),
            fsync: Self::default_fsync(),
        }
    }
}

/// Observability (logging and tracing) configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    /// Tracing log level filter (trace, debug, info, warn, error).
    #[serde(default = "ObservabilityConfig::default_log_level")]
    pub log_level: String,
    /// Log output format: "text" or "json".
    #[serde(default = "ObservabilityConfig::default_log_format")]
    pub log_format: String,
}

impl ObservabilityConfig {
    fn default_log_level() -> String {
        "info".to_string()
    }

    fn default_log_format() -> String {
        "text".to_string()
    }

    /// Valid log level strings.
    pub(crate) const VALID_LOG_LEVELS: &'static [&'static str] =
        &["trace", "debug", "info", "warn", "error"];

    /// Valid log format strings.
    pub(crate) const VALID_LOG_FORMATS: &'static [&'static str] = &["text", "json"];
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: Self::default_log_level(),
            log_format: Self::default_log_format(),
        }
    }
}

/// Operational limits and timeouts.
#[derive(Debug, Clone, Deserialize)]
pub struct OperationalConfig {
    /// Request timeout in seconds.
    #[serde(default = "OperationalConfig::default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Graceful shutdown timeout in seconds.
    #[serde(default = "OperationalConfig::default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
    /// Maximum concurrent connections.
    #[serde(default = "OperationalConfig::default_max_connections")]
    pub max_connections: u32,
    /// Internal work queue depth.
    #[serde(default = "OperationalConfig::default_queue_depth")]
    pub queue_depth: u32,
}

impl OperationalConfig {
    const fn default_request_timeout_secs() -> u64 {
        30
    }

    const fn default_shutdown_timeout_secs() -> u64 {
        10
    }

    const fn default_max_connections() -> u32 {
        1024
    }

    const fn default_queue_depth() -> u32 {
        4096
    }
}

impl Default for OperationalConfig {
    fn default() -> Self {
        Self {
            request_timeout_secs: Self::default_request_timeout_secs(),
            shutdown_timeout_secs: Self::default_shutdown_timeout_secs(),
            max_connections: Self::default_max_connections(),
            queue_depth: Self::default_queue_depth(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_defaults() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.bind_address, "127.0.0.1");
        assert_eq!(cfg.port, 8420);
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
    }

    #[test]
    fn storage_section_defaults() {
        let cfg = StorageSection::default();
        assert_eq!(cfg.data_dir, "./data");
        assert_eq!(cfg.wal_max_size_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.memtable_flush_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.hot_tier_capacity, 10_000);
        assert!(cfg.fsync);
    }

    #[test]
    fn observability_config_defaults() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.log_format, "text");
    }

    #[test]
    fn operational_config_defaults() {
        let cfg = OperationalConfig::default();
        assert_eq!(cfg.request_timeout_secs, 30);
        assert_eq!(cfg.shutdown_timeout_secs, 10);
        assert_eq!(cfg.max_connections, 1024);
        assert_eq!(cfg.queue_depth, 4096);
    }
}
