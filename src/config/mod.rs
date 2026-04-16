//! Configuration loading, validation, and defaults.
//!
//! Loads YAML configuration with environment variable substitution,
//! validates values, and provides production-safe defaults.

mod env;
pub mod error;
mod types;

pub use error::ConfigError;
pub use types::{
    EmailConfig, EmailTransport, ObservabilityConfig, OnboardingConfig, OperationalConfig,
    ServerConfig, SmtpConfig, SmtpEncryption, StorageSection,
};

/// Helper: construct a validation error without repeating the struct
/// literal everywhere the email validator fires.
fn invalid(field: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::ValidationError {
        field: field.to_string(),
        reason: reason.into(),
    }
}

use serde::Deserialize;
use std::path::Path;

/// Top-level Hearth configuration.
///
/// All sections use `#[serde(default)]` so a partial or empty YAML file
/// produces valid configuration with production-safe defaults.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    /// Server network settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Storage engine settings.
    #[serde(default)]
    pub storage: StorageSection,
    /// Logging and tracing settings.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Operational limits and timeouts.
    #[serde(default)]
    pub operational: OperationalConfig,
    /// Outbound email delivery settings.
    #[serde(default)]
    pub email: EmailConfig,
    /// First-run onboarding settings.
    #[serde(default)]
    pub onboarding: OnboardingConfig,
    /// Whether development mode is active. Not serialized — set by [`Config::dev`].
    #[serde(skip)]
    pub dev_mode: bool,
}

impl Config {
    /// Parses a YAML string into a validated [`Config`].
    ///
    /// Environment variables referenced as `${VAR_NAME}` are substituted
    /// before parsing. Returns an error for invalid YAML, missing env vars,
    /// or values that fail validation.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, ConfigError> {
        let substituted = env::substitute_env_vars(yaml)?;
        let config: Self = serde_yaml::from_str(&substituted)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Loads configuration from a YAML file on disk.
    ///
    /// Before reading the YAML, looks for a `.env` file in the same directory
    /// as `path` and loads it if present (missing `.env` is silently ignored).
    /// Variables already set in the process environment take precedence over
    /// `.env` values. After that, substitutes `${VAR}` references, parses
    /// YAML, and validates the result.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        if let Some(dir) = path.parent() {
            env::load_dotenv(&dir.join(".env"))?;
        }
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    /// Creates a development-mode configuration with relaxed settings.
    ///
    /// Intended for local development and testing:
    /// - `fsync` disabled for faster writes
    /// - No TLS
    /// - Debug-level logging
    /// - Relaxed validation (empty `data_dir` allowed)
    pub fn dev() -> Self {
        Self {
            server: ServerConfig {
                bind_address: "127.0.0.1".to_string(),
                port: 8420,
                tls_cert_path: None,
                tls_key_path: None,
                tls_client_ca_path: None,
                tls_require_client_cert: false,
            },
            storage: StorageSection {
                data_dir: String::new(),
                wal_max_size_bytes: 64 * 1024 * 1024,
                memtable_flush_bytes: 16 * 1024 * 1024,
                hot_tier_capacity: 1_000,
                fsync: false,
            },
            observability: ObservabilityConfig {
                log_level: "debug".to_string(),
                log_format: "text".to_string(),
            },
            operational: OperationalConfig::default(),
            email: EmailConfig::default(),
            onboarding: OnboardingConfig::default(),
            dev_mode: true,
        }
    }

    /// Validates configuration values.
    ///
    /// Called automatically by [`from_yaml_str`] and [`from_file`].
    /// Dev-mode configs skip certain checks (e.g., empty `data_dir`).
    fn validate(&self) -> Result<(), ConfigError> {
        // Port: valid TCP port range
        if self.server.port == 0 {
            return Err(ConfigError::ValidationError {
                field: "server.port".to_string(),
                reason: "must be between 1 and 65535".to_string(),
            });
        }

        // TLS: cert and key must both be present or both absent
        match (&self.server.tls_cert_path, &self.server.tls_key_path) {
            (Some(_), None) => {
                return Err(ConfigError::ValidationError {
                    field: "server.tls_key_path".to_string(),
                    reason: "tls_key_path is required when tls_cert_path is set".to_string(),
                });
            }
            (None, Some(_)) => {
                return Err(ConfigError::ValidationError {
                    field: "server.tls_cert_path".to_string(),
                    reason: "tls_cert_path is required when tls_key_path is set".to_string(),
                });
            }
            _ => {}
        }

        // mTLS: require_client_cert needs a CA path
        if self.server.tls_require_client_cert && self.server.tls_client_ca_path.is_none() {
            return Err(ConfigError::ValidationError {
                field: "server.tls_client_ca_path".to_string(),
                reason: "tls_client_ca_path is required when tls_require_client_cert is true"
                    .to_string(),
            });
        }

        // Data directory: must not be empty in production mode
        if !self.dev_mode && self.storage.data_dir.is_empty() {
            return Err(ConfigError::ValidationError {
                field: "storage.data_dir".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        // Log level: must be a recognized level
        if !ObservabilityConfig::VALID_LOG_LEVELS.contains(&self.observability.log_level.as_str()) {
            return Err(ConfigError::ValidationError {
                field: "observability.log_level".to_string(),
                reason: format!(
                    "must be one of: {}",
                    ObservabilityConfig::VALID_LOG_LEVELS.join(", ")
                ),
            });
        }

        // Log format: must be recognized
        if !ObservabilityConfig::VALID_LOG_FORMATS.contains(&self.observability.log_format.as_str())
        {
            return Err(ConfigError::ValidationError {
                field: "observability.log_format".to_string(),
                reason: format!(
                    "must be one of: {}",
                    ObservabilityConfig::VALID_LOG_FORMATS.join(", ")
                ),
            });
        }

        // Timeouts: must be positive
        if self.operational.request_timeout_secs == 0 {
            return Err(ConfigError::ValidationError {
                field: "operational.request_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if self.operational.shutdown_timeout_secs == 0 {
            return Err(ConfigError::ValidationError {
                field: "operational.shutdown_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        // Connections and queue depth: must be positive
        if self.operational.max_connections == 0 {
            return Err(ConfigError::ValidationError {
                field: "operational.max_connections".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if self.operational.queue_depth == 0 {
            return Err(ConfigError::ValidationError {
                field: "operational.queue_depth".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        validate_email(&self.email)?;

        // notification_email: if set, must be a valid RFC 5322 mailbox
        if let Some(addr) = &self.onboarding.notification_email {
            addr.parse::<lettre::message::Mailbox>().map_err(|e| {
                invalid(
                    "onboarding.notification_email",
                    format!("could not parse as an RFC 5322 mailbox: {e}"),
                )
            })?;
        }

        Ok(())
    }
}

/// Validates the `email` section. Only the `Smtp` transport has
/// structural requirements today (`Log` accepts any `from`/`smtp`
/// combination, including `None`).
fn validate_email(email: &EmailConfig) -> Result<(), ConfigError> {
    if email.transport != EmailTransport::Smtp {
        return Ok(());
    }

    let smtp = email.smtp.as_ref().ok_or_else(|| {
        invalid(
            "email.smtp",
            "smtp block is required when email.transport is smtp",
        )
    })?;

    let from = email.from.as_ref().ok_or_else(|| {
        invalid(
            "email.from",
            "from address is required when email.transport is smtp",
        )
    })?;
    from.parse::<lettre::message::Mailbox>().map_err(|e| {
        invalid(
            "email.from",
            format!("could not parse as an RFC 5322 mailbox: {e}"),
        )
    })?;

    // Credentials: either both or neither. Mismatched halves are rejected.
    match (&smtp.username, &smtp.password) {
        (Some(u), _) if u.is_empty() => {
            return Err(invalid("email.smtp.username", "must not be empty"));
        }
        (Some(_), None) => {
            return Err(invalid(
                "email.smtp.password",
                "password is required when username is set",
            ));
        }
        (None, Some(_)) => {
            return Err(invalid(
                "email.smtp.username",
                "username is required when password is set",
            ));
        }
        _ => {}
    }

    if smtp.host.is_empty() {
        return Err(invalid("email.smtp.host", "must not be empty"));
    }
    if smtp.port == 0 {
        return Err(invalid("email.smtp.port", "must be between 1 and 65535"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // === TEST_SCENARIOS #1: Parse valid YAML config ===

    #[test]
    fn parse_valid_yaml_config() {
        let yaml = r#"
server:
  bind_address: "0.0.0.0"
  port: 9090
storage:
  data_dir: "/var/lib/hearth"
  wal_max_size_bytes: 134217728
  memtable_flush_bytes: 33554432
  hot_tier_capacity: 5000
  fsync: true
observability:
  log_level: "warn"
  log_format: "json"
operational:
  request_timeout_secs: 60
  shutdown_timeout_secs: 30
  max_connections: 2048
  queue_depth: 8192
"#;
        let config = Config::from_yaml_str(yaml).expect("valid YAML should parse");

        assert_eq!(config.server.bind_address, "0.0.0.0");
        assert_eq!(config.server.port, 9090);
        assert!(config.server.tls_cert_path.is_none());

        assert_eq!(config.storage.data_dir, "/var/lib/hearth");
        assert_eq!(config.storage.wal_max_size_bytes, 128 * 1024 * 1024);
        assert_eq!(config.storage.memtable_flush_bytes, 32 * 1024 * 1024);
        assert_eq!(config.storage.hot_tier_capacity, 5000);
        assert!(config.storage.fsync);

        assert_eq!(config.observability.log_level, "warn");
        assert_eq!(config.observability.log_format, "json");

        assert_eq!(config.operational.request_timeout_secs, 60);
        assert_eq!(config.operational.shutdown_timeout_secs, 30);
        assert_eq!(config.operational.max_connections, 2048);
        assert_eq!(config.operational.queue_depth, 8192);

        assert!(!config.dev_mode);
    }

    // === TEST_SCENARIOS #3: Default values applied for omitted fields ===

    #[test]
    fn default_values_applied_for_omitted_fields() {
        let config = Config::from_yaml_str("{}").expect("empty YAML should use defaults");

        assert_eq!(config.server.bind_address, "127.0.0.1");
        assert_eq!(config.server.port, 8420);
        assert!(config.server.tls_cert_path.is_none());
        assert!(config.server.tls_key_path.is_none());

        assert_eq!(config.storage.data_dir, "./data");
        assert_eq!(config.storage.wal_max_size_bytes, 256 * 1024 * 1024);
        assert_eq!(config.storage.memtable_flush_bytes, 64 * 1024 * 1024);
        assert_eq!(config.storage.hot_tier_capacity, 10_000);
        assert!(config.storage.fsync);

        assert_eq!(config.observability.log_level, "info");
        assert_eq!(config.observability.log_format, "text");

        assert_eq!(config.operational.request_timeout_secs, 30);
        assert_eq!(config.operational.shutdown_timeout_secs, 10);
        assert_eq!(config.operational.max_connections, 1024);
        assert_eq!(config.operational.queue_depth, 4096);

        assert!(!config.dev_mode);
    }

    #[test]
    fn partial_override_preserves_other_defaults() {
        let yaml = r#"
server:
  port: 3000
storage:
  data_dir: "/custom/path"
"#;
        let config = Config::from_yaml_str(yaml).expect("partial YAML should parse");

        // Overridden values
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.storage.data_dir, "/custom/path");

        // Remaining defaults preserved
        assert_eq!(config.server.bind_address, "127.0.0.1");
        assert!(config.storage.fsync);
        assert_eq!(config.observability.log_level, "info");
        assert_eq!(config.operational.request_timeout_secs, 30);
    }

    // === TEST_SCENARIOS #2: Reject invalid config ===

    #[test]
    fn reject_invalid_yaml_syntax() {
        let bad_yaml = "server:\n  port: [unclosed";
        let result = Config::from_yaml_str(bad_yaml);
        assert!(result.is_err());
        let err = result.expect_err("should be a config error");
        let display = format!("{err}");
        assert!(display.contains("parse"), "got: {display}");
    }

    #[test]
    fn reject_invalid_port_zero() {
        let yaml = "server:\n  port: 0";
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_err());
        let err = result.expect_err("should be a config error");
        let display = format!("{err}");
        assert!(display.contains("server.port"), "got: {display}");
        assert!(display.contains("65535"), "got: {display}");
    }

    #[test]
    fn reject_negative_timeout() {
        let yaml = "operational:\n  request_timeout_secs: 0";
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_err());
        let err = result.expect_err("should be a config error");
        let display = format!("{err}");
        assert!(display.contains("request_timeout_secs"), "got: {display}");
        assert!(display.contains("greater than 0"), "got: {display}");
    }

    #[test]
    fn reject_invalid_log_level() {
        let yaml = "observability:\n  log_level: \"verbose\"";
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_err());
        let err = result.expect_err("should be a config error");
        let display = format!("{err}");
        assert!(display.contains("log_level"), "got: {display}");
    }

    #[test]
    fn reject_empty_data_dir_in_prod_mode() {
        let yaml = "storage:\n  data_dir: \"\"";
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_err());
        let err = result.expect_err("should be a config error");
        let display = format!("{err}");
        assert!(display.contains("data_dir"), "got: {display}");
    }

    #[test]
    fn reject_invalid_log_format() {
        let yaml = "observability:\n  log_format: \"xml\"";
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_err());
        let err = result.expect_err("should be a config error");
        let display = format!("{err}");
        assert!(display.contains("log_format"), "got: {display}");
    }

    // === TEST_SCENARIOS #4: Dev mode ===

    #[test]
    fn dev_mode_defaults() {
        let config = Config::dev();

        assert!(config.dev_mode);
        assert!(!config.storage.fsync, "dev mode should disable fsync");
        assert!(
            config.server.tls_cert_path.is_none(),
            "dev mode should have no TLS"
        );
        assert!(
            config.server.tls_key_path.is_none(),
            "dev mode should have no TLS"
        );
        assert_eq!(
            config.observability.log_level, "debug",
            "dev mode should use debug logging"
        );
    }

    #[test]
    fn dev_mode_allows_relaxed_validation() {
        let config = Config::dev();
        // Dev config has empty data_dir — validate should not reject it
        assert!(config.storage.data_dir.is_empty());
        // Validate directly to confirm relaxed rules
        assert!(config.validate().is_ok());
    }

    // === File loading ===

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("hearth.yaml");
        std::fs::write(
            &config_path,
            "server:\n  port: 7777\nstorage:\n  data_dir: /tmp/hearth\n",
        )
        .expect("write config file");

        let config = Config::from_file(&config_path).expect("load from file");
        assert_eq!(config.server.port, 7777);
        assert_eq!(config.storage.data_dir, "/tmp/hearth");
    }

    #[test]
    fn from_file_auto_loads_dotenv_sibling() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join(".env"),
            "HEARTH_FFILE_DOTENV_PORT=7654\nHEARTH_FFILE_DOTENV_DIR=/dotenv/data\n",
        )
        .expect("write .env");
        std::fs::write(
            dir.path().join("hearth.yaml"),
            "server:\n  port: ${HEARTH_FFILE_DOTENV_PORT}\nstorage:\n  data_dir: ${HEARTH_FFILE_DOTENV_DIR}\n",
        )
        .expect("write hearth.yaml");

        std::env::remove_var("HEARTH_FFILE_DOTENV_PORT");
        std::env::remove_var("HEARTH_FFILE_DOTENV_DIR");

        let config =
            Config::from_file(&dir.path().join("hearth.yaml")).expect("load with .env sibling");
        assert_eq!(config.server.port, 7654);
        assert_eq!(config.storage.data_dir, "/dotenv/data");

        std::env::remove_var("HEARTH_FFILE_DOTENV_PORT");
        std::env::remove_var("HEARTH_FFILE_DOTENV_DIR");
    }

    #[test]
    fn from_file_real_env_beats_dotenv() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(dir.path().join(".env"), "HEARTH_FFILE_PRIORITY=from_dotenv\n")
            .expect("write .env");
        std::fs::write(
            dir.path().join("hearth.yaml"),
            "storage:\n  data_dir: ${HEARTH_FFILE_PRIORITY}\n",
        )
        .expect("write hearth.yaml");

        std::env::set_var("HEARTH_FFILE_PRIORITY", "from_real_env");

        let config =
            Config::from_file(&dir.path().join("hearth.yaml")).expect("real env takes precedence");
        assert_eq!(config.storage.data_dir, "from_real_env");

        std::env::remove_var("HEARTH_FFILE_PRIORITY");
    }

    #[test]
    fn load_from_missing_file_returns_error() {
        let result = Config::from_file(Path::new("/nonexistent/hearth.yaml"));
        assert!(result.is_err());
        let err = result.expect_err("should be a config error");
        let display = format!("{err}");
        assert!(display.contains("read configuration"), "got: {display}");
    }

    // === Env var integration ===

    #[test]
    fn from_yaml_str_with_env_vars() {
        std::env::set_var("HEARTH_CFG_PORT", "4242");
        std::env::set_var("HEARTH_CFG_DIR", "/opt/hearth");
        let yaml = r#"
server:
  port: ${HEARTH_CFG_PORT}
storage:
  data_dir: "${HEARTH_CFG_DIR}/data"
"#;
        let config = Config::from_yaml_str(yaml).expect("env var substitution");
        assert_eq!(config.server.port, 4242);
        assert_eq!(config.storage.data_dir, "/opt/hearth/data");
        std::env::remove_var("HEARTH_CFG_PORT");
        std::env::remove_var("HEARTH_CFG_DIR");
    }

    // === TLS config validation ===

    #[test]
    fn reject_cert_without_key() {
        let yaml = r#"
server:
  tls_cert_path: "/etc/hearth/cert.pem"
storage:
  data_dir: "/tmp/hearth"
"#;
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_err());
        let display = format!("{}", result.expect_err("should fail"));
        assert!(display.contains("tls_key_path"), "got: {display}");
    }

    #[test]
    fn reject_key_without_cert() {
        let yaml = r#"
server:
  tls_key_path: "/etc/hearth/key.pem"
storage:
  data_dir: "/tmp/hearth"
"#;
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_err());
        let display = format!("{}", result.expect_err("should fail"));
        assert!(display.contains("tls_cert_path"), "got: {display}");
    }

    #[test]
    fn reject_require_client_cert_without_ca() {
        let yaml = r#"
server:
  tls_cert_path: "/etc/hearth/cert.pem"
  tls_key_path: "/etc/hearth/key.pem"
  tls_require_client_cert: true
storage:
  data_dir: "/tmp/hearth"
"#;
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_err());
        let display = format!("{}", result.expect_err("should fail"));
        assert!(display.contains("tls_client_ca_path"), "got: {display}");
    }

    #[test]
    fn accept_valid_tls_config() {
        let yaml = r#"
server:
  tls_cert_path: "/etc/hearth/cert.pem"
  tls_key_path: "/etc/hearth/key.pem"
  tls_client_ca_path: "/etc/hearth/ca.pem"
  tls_require_client_cert: true
storage:
  data_dir: "/tmp/hearth"
"#;
        let result = Config::from_yaml_str(yaml);
        assert!(result.is_ok(), "valid TLS config should pass: {result:?}");
    }

    // === Config is Send + Sync (for Arc<Config>) ===

    #[test]
    fn config_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Config>();
    }

    // === Email / SMTP validation ===

    #[test]
    fn email_smtp_requires_smtp_block() {
        let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  from: "auth@example.com"
"#;
        let err = Config::from_yaml_str(yaml).expect_err("missing smtp should fail");
        let display = format!("{err}");
        assert!(display.contains("email.smtp"), "got: {display}");
    }

    #[test]
    fn email_smtp_requires_from() {
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
    fn email_smtp_rejects_malformed_from() {
        let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  from: "not an address"
  smtp:
    host: "smtp.example.com"
    port: 587
"#;
        let err = Config::from_yaml_str(yaml).expect_err("malformed from should fail");
        let display = format!("{err}");
        assert!(display.contains("email.from"), "got: {display}");
    }

    #[test]
    fn email_smtp_rejects_username_without_password() {
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
        let err = Config::from_yaml_str(yaml).expect_err("missing password should fail");
        let display = format!("{err}");
        assert!(display.contains("email.smtp.password"), "got: {display}");
    }

    #[test]
    fn email_smtp_rejects_password_without_username() {
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
        let err = Config::from_yaml_str(yaml).expect_err("missing username should fail");
        let display = format!("{err}");
        assert!(display.contains("email.smtp.username"), "got: {display}");
    }

    #[test]
    fn email_smtp_accepts_minimal_valid_config() {
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
        let config = Config::from_yaml_str(yaml).expect("valid SMTP config should parse");
        assert_eq!(config.email.transport, EmailTransport::Smtp);
        let smtp = config.email.smtp.as_ref().expect("smtp present");
        assert_eq!(smtp.host, "mailpit");
        assert_eq!(smtp.port, 1025);
        assert_eq!(smtp.encryption, SmtpEncryption::None);
        assert!(smtp.username.is_none());
    }

    #[test]
    fn onboarding_notification_email_accepts_valid_address() {
        let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
onboarding:
  notification_email: "ops@example.com"
"#;
        let config = Config::from_yaml_str(yaml).expect("valid notification_email should parse");
        assert_eq!(
            config.onboarding.notification_email.as_deref(),
            Some("ops@example.com")
        );
    }

    #[test]
    fn onboarding_notification_email_rejects_malformed_address() {
        let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
onboarding:
  notification_email: "not an address"
"#;
        let err =
            Config::from_yaml_str(yaml).expect_err("malformed notification_email should fail");
        let display = format!("{err}");
        assert!(
            display.contains("onboarding.notification_email"),
            "got: {display}"
        );
    }

    #[test]
    fn onboarding_notification_email_accepts_absent() {
        let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
onboarding: {}
"#;
        let config = Config::from_yaml_str(yaml).expect("absent notification_email is fine");
        assert!(config.onboarding.notification_email.is_none());
    }

    #[test]
    fn email_smtp_accepts_credentialed_config() {
        let yaml = r#"
storage:
  data_dir: "/tmp/hearth"
email:
  transport: smtp
  from: "auth@example.com"
  smtp:
    host: "smtp.example.com"
    port: 587
    encryption: starttls
    username: "notifications"
    password: "hunter2"
"#;
        let config = Config::from_yaml_str(yaml).expect("credentialed config should parse");
        let smtp = config.email.smtp.expect("smtp present");
        assert_eq!(smtp.encryption, SmtpEncryption::Starttls);
        assert_eq!(smtp.username.as_deref(), Some("notifications"));
        assert_eq!(smtp.password.as_deref(), Some("hunter2"));
    }
}
