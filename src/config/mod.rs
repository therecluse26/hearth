//! Configuration loading, validation, and defaults.
//!
//! Loads YAML configuration with environment variable substitution,
//! validates values, and provides production-safe defaults.

mod env;
pub mod error;
mod types;

pub use env::{EnvVarWarning, EnvVarWarningKind};
pub use error::ConfigError;
pub use types::parse_duration_to_micros;
pub use types::{
    ApplicationYamlConfig, AuthConfig, BrandingConfig, ClaimsYamlConfig, CompactionSection,
    EmailConfig, EmailTransport, FederationProviderYaml, FederationYamlConfig, LinkModeYaml,
    MailgunConfig, MailgunRegion, MailtrapConfig, MetricsConfig, ObservabilityConfig, OidcYamlConfig,
    OnboardingConfig, OperationalConfig, OrgConfigYaml, OrganizationYamlConfig, PasswordPolicyYaml,
    PermissionYamlConfig, PostmarkConfig, ProtectedResourceYamlConfig, RateLimitYaml,
    RealmAuthYaml, RealmEmailYaml, RealmScimYaml, RealmTokenYaml, RealmWebYaml, RealmYamlConfig,
    RoleYamlConfig, SamlServiceProviderYaml, ScopeBundleYamlConfig, SendgridConfig, ServerConfig,
    SmtpConfig, SmtpEncryption, StorageSection, TokenYamlConfig,
};

/// Helper: construct a validation error without repeating the struct
/// literal everywhere the email validator fires.
fn invalid(field: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::ValidationError {
        field: field.to_string(),
        reason: reason.into(),
    }
}

/// A single validation issue with its field path and human-readable reason.
///
/// Used by [`Config::validate_all`] to report all problems at once rather
/// than short-circuiting on the first error.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationIssue {
    /// Dot-delimited config field path (e.g. `"server.port"`).
    pub field: String,
    /// Human-readable reason this value is invalid.
    pub reason: String,
}

use serde::Deserialize;
use std::path::Path;

/// Valid UI theme names — must match `protocol::web::themes::VALID_THEMES`.
const VALID_UI_THEMES: &[&str] = &["ember", "ocean", "midnight", "forest", "cloud", "slate"];

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
    /// Global branding settings (logo URL).
    #[serde(default)]
    pub branding: BrandingConfig,
    /// OIDC / OAuth 2.0 settings (issuer URL, authorization code TTL, nonce enforcement).
    #[serde(default)]
    pub oidc: OidcYamlConfig,
    /// Token issuance settings (issuer, audience, access/refresh TTLs).
    #[serde(default)]
    pub token: TokenYamlConfig,
    /// Global authentication defaults (session TTL, password hashing params).
    #[serde(default)]
    pub auth: AuthConfig,
    /// Prometheus metrics endpoint settings.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Per-realm configuration overrides.
    ///
    /// When `Some`, realms are declaratively managed: YAML entries become
    /// Active realms, storage-only realms get Archived. When `None`,
    /// realms are managed via API/onboarding (backward compatible).
    #[serde(default)]
    pub realms: Option<std::collections::HashMap<String, RealmYamlConfig>>,
    /// Whether development mode is active. Not serialized — set by [`Config::dev`].
    #[serde(skip)]
    pub dev_mode: bool,
    /// Env-var substitution warnings from config loading (missing/empty variables).
    /// Skipped during serde deserialization — populated by [`Config::from_file`]
    /// and [`Config::from_yaml_str`].
    #[serde(skip)]
    pub config_warnings: Vec<EnvVarWarning>,
}

impl Config {
    /// Parses a YAML string into a validated [`Config`].
    ///
    /// Environment variables referenced as `${VAR_NAME}` or
    /// `${VAR_NAME:-default}` are substituted before parsing. Missing or
    /// empty variables (without a default) produce warnings rather than
    /// errors — see [`EnvVarWarning`].
    ///
    /// Returns an error for invalid YAML or values that fail validation.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, ConfigError> {
        let (substituted, warnings) = env::substitute_env_vars(yaml);
        let mut config: Self = serde_yaml::from_str(&substituted)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.config_warnings = warnings;
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
                trusted_proxies: Vec::new(),
                default_realm: None,
                grpc_port: None,
                grpc_bind_address: None,
                assets_dir: None,
            },
            storage: StorageSection {
                data_dir: String::new(),
                wal_max_size_bytes: 64 * 1024 * 1024,
                memtable_flush_bytes: 16 * 1024 * 1024,
                hot_tier_capacity: Some(1_000),
                hot_tier_max_memory: None,
                fsync: false,
                compaction: CompactionSection::default(),
            },
            observability: ObservabilityConfig {
                log_level: "debug".to_string(),
                log_format: "text".to_string(),
            },
            operational: OperationalConfig::default(),
            email: EmailConfig::default(),
            onboarding: OnboardingConfig::default(),
            branding: BrandingConfig::default(),
            oidc: OidcYamlConfig::default(),
            token: TokenYamlConfig::default(),
            auth: AuthConfig::default(),
            metrics: MetricsConfig::default(),
            realms: None,
            dev_mode: true,
            config_warnings: Vec::new(),
        }
    }

    /// Parses a YAML string into a [`Config`] *without* running validation.
    ///
    /// Use this when you want to run [`validate_all`] yourself to collect
    /// all issues rather than short-circuiting on the first error.
    ///
    /// Environment variables are still substituted.
    pub fn from_yaml_str_unchecked(yaml: &str) -> Result<Self, ConfigError> {
        let (substituted, warnings) = env::substitute_env_vars(yaml);
        let mut config: Self = serde_yaml::from_str(&substituted)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.config_warnings = warnings;
        Ok(config)
    }

    /// Validates all configuration values, collecting every issue.
    ///
    /// Unlike [`validate`], this does **not** short-circuit — all validation
    /// rules are checked and every problem is returned.
    pub fn validate_all(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        // Port
        if self.server.port == 0 {
            issues.push(ValidationIssue {
                field: "server.port".to_string(),
                reason: "must be between 1 and 65535".to_string(),
            });
        }

        // TLS cert/key pairing
        match (&self.server.tls_cert_path, &self.server.tls_key_path) {
            (Some(_), None) => issues.push(ValidationIssue {
                field: "server.tls_key_path".to_string(),
                reason: "tls_key_path is required when tls_cert_path is set".to_string(),
            }),
            (None, Some(_)) => issues.push(ValidationIssue {
                field: "server.tls_cert_path".to_string(),
                reason: "tls_cert_path is required when tls_key_path is set".to_string(),
            }),
            _ => {}
        }

        // mTLS
        if self.server.tls_require_client_cert && self.server.tls_client_ca_path.is_none() {
            issues.push(ValidationIssue {
                field: "server.tls_client_ca_path".to_string(),
                reason: "tls_client_ca_path is required when tls_require_client_cert is true"
                    .to_string(),
            });
        }

        // Data directory
        if !self.dev_mode && self.storage.data_dir.is_empty() {
            issues.push(ValidationIssue {
                field: "storage.data_dir".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        // Log level
        if !ObservabilityConfig::VALID_LOG_LEVELS.contains(&self.observability.log_level.as_str()) {
            issues.push(ValidationIssue {
                field: "observability.log_level".to_string(),
                reason: format!(
                    "must be one of: {}",
                    ObservabilityConfig::VALID_LOG_LEVELS.join(", ")
                ),
            });
        }

        // Log format
        if !ObservabilityConfig::VALID_LOG_FORMATS.contains(&self.observability.log_format.as_str())
        {
            issues.push(ValidationIssue {
                field: "observability.log_format".to_string(),
                reason: format!(
                    "must be one of: {}",
                    ObservabilityConfig::VALID_LOG_FORMATS.join(", ")
                ),
            });
        }

        // Operational timeouts and limits
        if self.operational.request_timeout_secs == 0 {
            issues.push(ValidationIssue {
                field: "operational.request_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.operational.shutdown_timeout_secs == 0 {
            issues.push(ValidationIssue {
                field: "operational.shutdown_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.operational.max_connections == 0 {
            issues.push(ValidationIssue {
                field: "operational.max_connections".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.operational.queue_depth == 0 {
            issues.push(ValidationIssue {
                field: "operational.queue_depth".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        // OIDC
        validate_oidc_all(&self.oidc, &mut issues);
        // Token
        validate_token_all(&self.token, &mut issues);
        // Email
        validate_email_all(&self.email, &mut issues);
        // Branding
        validate_branding_all(&self.branding, &mut issues);
        // Realm configs
        if let Some(realms) = self.realms.as_ref() {
            if realms.contains_key("system") {
                issues.push(ValidationIssue {
                    field: "realms.system".to_string(),
                    reason: "\"system\" is a reserved realm name; managed by Hearth".to_string(),
                });
            }
        }
        validate_realm_web_configs_all(self.realms.as_ref(), &mut issues);
        validate_realm_auth_configs_all(self.realms.as_ref(), &mut issues);
        validate_realm_applications_all(self.realms.as_ref(), &mut issues);
        validate_realm_organizations_all(self.realms.as_ref(), &mut issues);

        // Notification email
        if let Some(addr) = &self.onboarding.notification_email {
            if addr.parse::<lettre::message::Mailbox>().is_err() {
                issues.push(ValidationIssue {
                    field: "onboarding.notification_email".to_string(),
                    reason: "could not parse as an RFC 5322 mailbox".to_string(),
                });
            }
        }

        issues
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

        validate_oidc(&self.oidc)?;
        validate_token(&self.token)?;
        validate_email(&self.email)?;
        validate_branding(&self.branding)?;
        validate_realm_names(self.realms.as_ref())?;
        validate_realm_web_configs(self.realms.as_ref())?;
        validate_realm_auth_configs(self.realms.as_ref())?;
        validate_realm_applications(self.realms.as_ref())?;
        validate_realm_organizations(self.realms.as_ref())?;

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

/// Rejects YAML `realms.system`. The system realm is Hearth-owned; it
/// must not be declared or reconciled by operators. See the admin-realm
/// architecture note in `memory/admin_realm.md`.
fn validate_realm_names(
    realms: Option<&std::collections::HashMap<String, types::RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else { return Ok(()) };
    if realms.contains_key("system") {
        return Err(invalid(
            "realms.system",
            "\"system\" is a reserved realm name; it is managed by Hearth and cannot be declared in YAML",
        ));
    }
    Ok(())
}

/// Validates the `branding` section.
fn validate_branding(branding: &BrandingConfig) -> Result<(), ConfigError> {
    if let Some(theme) = &branding.theme {
        let lower = theme.to_ascii_lowercase();
        if !VALID_UI_THEMES.contains(&lower.as_str()) {
            return Err(invalid(
                "branding.theme",
                format!(
                    "unknown theme '{}'; valid themes are: {}",
                    theme,
                    VALID_UI_THEMES.join(", ")
                ),
            ));
        }
    }
    if let Some(path) = &branding.custom_css {
        if !std::fs::metadata(path)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            return Err(invalid(
                "branding.custom_css",
                format!("file not found or not readable: {path}"),
            ));
        }
    }
    Ok(())
}

/// Validates per-realm `web:` branding blocks.
fn validate_realm_web_configs(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else {
        return Ok(());
    };
    for (name, cfg) in realms {
        let Some(web) = &cfg.web else { continue };
        if let Some(theme) = &web.theme {
            let lower = theme.to_ascii_lowercase();
            if !VALID_UI_THEMES.contains(&lower.as_str()) {
                return Err(invalid(
                    &format!("realms.{name}.web.theme"),
                    format!(
                        "unknown theme '{}'; valid themes are: {}",
                        theme,
                        VALID_UI_THEMES.join(", ")
                    ),
                ));
            }
        }
        if let Some(path) = &web.custom_css {
            if !std::fs::metadata(path)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                return Err(invalid(
                    &format!("realms.{name}.web.custom_css"),
                    format!("file not found or not readable: {path}"),
                ));
            }
        }
    }
    Ok(())
}

/// Valid MFA method names.
const VALID_MFA_METHODS: &[&str] = &["totp", "webauthn"];

/// Valid authentication method names.
const VALID_AUTH_METHODS: &[&str] = &["password", "magic_link", "passkey"];

/// Validates per-realm `auth:` policy blocks.
fn validate_realm_auth_configs(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else {
        return Ok(());
    };
    for (name, cfg) in realms {
        if let Some(scim) = &cfg.scim {
            if let Some(token) = &scim.bearer_token {
                if token.trim().is_empty() {
                    return Err(invalid(
                        &format!("realms.{name}.scim.bearer_token"),
                        "must not be empty when SCIM is configured",
                    ));
                }
            }
        }
        let Some(auth) = &cfg.auth else { continue };
        if let Some(methods) = &auth.mfa_methods {
            for m in methods {
                if !VALID_MFA_METHODS.contains(&m.as_str()) {
                    return Err(invalid(
                        &format!("realms.{name}.auth.mfa_methods"),
                        format!(
                            "unknown MFA method '{}'; valid methods are: {}",
                            m,
                            VALID_MFA_METHODS.join(", ")
                        ),
                    ));
                }
            }
        }
        if let Some(methods) = &auth.allowed_auth_methods {
            for m in methods {
                if !VALID_AUTH_METHODS.contains(&m.as_str()) {
                    return Err(invalid(
                        &format!("realms.{name}.auth.allowed_auth_methods"),
                        format!(
                            "unknown auth method '{}'; valid methods are: {}",
                            m,
                            VALID_AUTH_METHODS.join(", ")
                        ),
                    ));
                }
            }
        }
        if let Some(pp) = &auth.password_policy {
            if let Some(len) = pp.min_length {
                if len == 0 {
                    return Err(invalid(
                        &format!("realms.{name}.auth.password_policy.min_length"),
                        "must be >= 1",
                    ));
                }
            }
        }
        if let Some(token) = &auth.token {
            if let Some(ttl) = &token.access_token_ttl {
                types::parse_duration_to_micros(ttl).map_err(|e| {
                    invalid(
                        &format!("realms.{name}.auth.token.access_token_ttl"),
                        format!("invalid duration: {e}"),
                    )
                })?;
            }
            if let Some(ttl) = &token.refresh_token_ttl {
                types::parse_duration_to_micros(ttl).map_err(|e| {
                    invalid(
                        &format!("realms.{name}.auth.token.refresh_token_ttl"),
                        format!("invalid duration: {e}"),
                    )
                })?;
            }
        }
        if let Some(rl) = &auth.rate_limit {
            if let Some(dur) = &rl.lockout_duration {
                types::parse_duration_to_micros(dur).map_err(|e| {
                    invalid(
                        &format!("realms.{name}.auth.rate_limit.lockout_duration"),
                        format!("invalid duration: {e}"),
                    )
                })?;
            }
        }
        if let Some(reg) = &auth.registration {
            if matches!(reg.mode, types::RegistrationModeYaml::DomainRestricted) {
                let missing = reg
                    .allowed_domains
                    .as_ref()
                    .map_or(true, std::vec::Vec::is_empty);
                if missing {
                    return Err(invalid(
                        &format!("realms.{name}.auth.registration.allowed_domains"),
                        "mode = domain_restricted requires a non-empty allowed_domains list",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Validates per-realm `organizations:` declarations.
fn validate_realm_organizations(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else {
        return Ok(());
    };
    for (realm_name, cfg) in realms {
        let Some(orgs) = &cfg.organizations else {
            continue;
        };
        for (slug, org) in orgs {
            let prefix = format!("realms.{realm_name}.organizations.{slug}");
            if org.name.trim().is_empty() {
                return Err(invalid(&format!("{prefix}.name"), "must not be empty"));
            }
            // The YAML key is the slug — validate slug format (lowercase alphanumeric + hyphens, 3-63 chars)
            if slug.len() < 3 || slug.len() > 63 {
                return Err(invalid(
                    &prefix,
                    format!("slug '{slug}' must be 3-63 characters"),
                ));
            }
            if !slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(invalid(
                    &prefix,
                    format!(
                        "slug '{slug}' must contain only lowercase letters, digits, and hyphens"
                    ),
                ));
            }
            if slug.starts_with('-') || slug.ends_with('-') {
                return Err(invalid(
                    &prefix,
                    format!("slug '{slug}' must not start or end with a hyphen"),
                ));
            }
        }
    }
    Ok(())
}

/// Valid OAuth 2.0 grant types.
const VALID_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
];

/// Validates per-realm `applications:` declarations.
fn validate_realm_applications(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else {
        return Ok(());
    };
    for (realm_name, cfg) in realms {
        let Some(apps) = cfg.oauth_clients.as_ref().or(cfg.applications.as_ref()) else {
            continue;
        };
        for (app_key, app) in apps {
            let prefix = format!("realms.{realm_name}.applications.{app_key}");
            if app.name.trim().is_empty() {
                return Err(invalid(&format!("{prefix}.name"), "must not be empty"));
            }
            if let Some(grant_types) = &app.grant_types {
                for gt in grant_types {
                    if !VALID_GRANT_TYPES.contains(&gt.as_str()) {
                        return Err(invalid(
                            &format!("{prefix}.grant_types"),
                            format!(
                                "unknown grant type '{}'; valid types are: {}",
                                gt,
                                VALID_GRANT_TYPES.join(", ")
                            ),
                        ));
                    }
                }
            }
            if let Some(uris) = &app.redirect_uris {
                for uri in uris {
                    if uri.is_empty() {
                        return Err(invalid(
                            &format!("{prefix}.redirect_uris"),
                            "redirect URIs must not be empty strings",
                        ));
                    }
                }
            }
            let is_confidential = app.confidential.unwrap_or(false);
            if is_confidential && app.client_secret.is_none() {
                return Err(invalid(
                    &format!("{prefix}.client_secret"),
                    "client_secret is required when confidential is true",
                ));
            }
            if !is_confidential && app.client_secret.is_some() {
                return Err(invalid(
                    &format!("{prefix}.confidential"),
                    "confidential must be true when client_secret is provided",
                ));
            }
        }
    }
    Ok(())
}

/// Validates the `oidc` section.
fn validate_oidc(oidc: &OidcYamlConfig) -> Result<(), ConfigError> {
    if let Some(issuer) = &oidc.issuer {
        if issuer.is_empty() {
            return Err(invalid("oidc.issuer", "must not be empty"));
        }
        // Issuer must look like a URL (starts with https:// or http://)
        if !issuer.starts_with("https://") && !issuer.starts_with("http://") {
            return Err(invalid(
                "oidc.issuer",
                "must be a URL starting with https:// or http://",
            ));
        }
    }
    if let Some(ttl) = &oidc.authorization_code_ttl {
        types::parse_duration_to_micros(ttl).map_err(|e| {
            invalid(
                "oidc.authorization_code_ttl",
                format!("invalid duration: {e}"),
            )
        })?;
    }
    Ok(())
}

/// Validates the `token` section.
fn validate_token(token: &TokenYamlConfig) -> Result<(), ConfigError> {
    if let Some(issuer) = &token.issuer {
        if issuer.is_empty() {
            return Err(invalid("token.issuer", "must not be empty"));
        }
    }
    if let Some(ttl) = &token.access_token_ttl {
        types::parse_duration_to_micros(ttl)
            .map_err(|e| invalid("token.access_token_ttl", format!("invalid duration: {e}")))?;
    }
    if let Some(ttl) = &token.refresh_token_ttl {
        types::parse_duration_to_micros(ttl)
            .map_err(|e| invalid("token.refresh_token_ttl", format!("invalid duration: {e}")))?;
    }
    Ok(())
}

/// Validates the `email` section.
///
/// Each transport has its own structural requirements. `Log` accepts
/// any combination (including all `None`).
fn validate_email(email: &EmailConfig) -> Result<(), ConfigError> {
    match email.transport {
        EmailTransport::Log => return Ok(()),
        EmailTransport::Smtp => validate_email_smtp(email)?,
        EmailTransport::Sendgrid => validate_email_sendgrid(email)?,
        EmailTransport::Postmark => validate_email_postmark(email)?,
        EmailTransport::Mailgun => validate_email_mailgun(email)?,
        EmailTransport::Mailtrap => validate_email_mailtrap(email)?,
    }
    Ok(())
}

/// Validates SMTP transport configuration.
fn validate_email_smtp(email: &EmailConfig) -> Result<(), ConfigError> {
    let smtp = email.smtp.as_ref().ok_or_else(|| {
        invalid(
            "email.smtp",
            "smtp block is required when email.transport is smtp",
        )
    })?;

    validate_from_address(email)?;

    // Credentials: either both or neither.
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

/// Validates `SendGrid` transport configuration.
fn validate_email_sendgrid(email: &EmailConfig) -> Result<(), ConfigError> {
    let sg = email.sendgrid.as_ref().ok_or_else(|| {
        invalid(
            "email.sendgrid",
            "sendgrid block is required when email.transport is sendgrid",
        )
    })?;
    validate_from_address(email)?;
    if sg.api_key.is_empty() {
        return Err(invalid("email.sendgrid.api_key", "must not be empty"));
    }
    Ok(())
}

/// Validates `Postmark` transport configuration.
fn validate_email_postmark(email: &EmailConfig) -> Result<(), ConfigError> {
    let pm = email.postmark.as_ref().ok_or_else(|| {
        invalid(
            "email.postmark",
            "postmark block is required when email.transport is postmark",
        )
    })?;
    validate_from_address(email)?;
    if pm.server_token.is_empty() {
        return Err(invalid("email.postmark.server_token", "must not be empty"));
    }
    Ok(())
}

/// Validates `Mailgun` transport configuration.
fn validate_email_mailgun(email: &EmailConfig) -> Result<(), ConfigError> {
    let mg = email.mailgun.as_ref().ok_or_else(|| {
        invalid(
            "email.mailgun",
            "mailgun block is required when email.transport is mailgun",
        )
    })?;
    validate_from_address(email)?;
    if mg.api_key.is_empty() {
        return Err(invalid("email.mailgun.api_key", "must not be empty"));
    }
    if mg.domain.is_empty() {
        return Err(invalid("email.mailgun.domain", "must not be empty"));
    }
    Ok(())
}

/// Validates `Mailtrap` transport configuration.
fn validate_email_mailtrap(email: &EmailConfig) -> Result<(), ConfigError> {
    let mt = email.mailtrap.as_ref().ok_or_else(|| {
        invalid(
            "email.mailtrap",
            "mailtrap block is required when email.transport is mailtrap",
        )
    })?;
    validate_from_address(email)?;
    if mt.api_key.is_empty() {
        return Err(invalid("email.mailtrap.api_key", "must not be empty"));
    }
    Ok(())
}

/// Validates the `from` address (shared across all non-log transports).
fn validate_from_address(email: &EmailConfig) -> Result<(), ConfigError> {
    let from = email.from.as_ref().ok_or_else(|| {
        invalid(
            "email.from",
            format!(
                "from address is required when email.transport is {:?}",
                email.transport
            ),
        )
    })?;
    from.parse::<lettre::message::Mailbox>().map_err(|e| {
        invalid(
            "email.from",
            format!("could not parse as an RFC 5322 mailbox: {e}"),
        )
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Accumulating validators (used by `validate_all`)
// ---------------------------------------------------------------------------

/// Collects OIDC validation issues without short-circuiting.
fn validate_oidc_all(oidc: &OidcYamlConfig, issues: &mut Vec<ValidationIssue>) {
    if let Some(issuer) = &oidc.issuer {
        if issuer.is_empty() {
            issues.push(ValidationIssue {
                field: "oidc.issuer".to_string(),
                reason: "must not be empty".to_string(),
            });
        } else if !issuer.starts_with("https://") && !issuer.starts_with("http://") {
            issues.push(ValidationIssue {
                field: "oidc.issuer".to_string(),
                reason: "must be a URL starting with https:// or http://".to_string(),
            });
        }
    }
    if let Some(ttl) = &oidc.authorization_code_ttl {
        if types::parse_duration_to_micros(ttl).is_err() {
            issues.push(ValidationIssue {
                field: "oidc.authorization_code_ttl".to_string(),
                reason: "invalid duration format".to_string(),
            });
        }
    }
}

/// Collects token validation issues without short-circuiting.
fn validate_token_all(token: &TokenYamlConfig, issues: &mut Vec<ValidationIssue>) {
    if let Some(issuer) = &token.issuer {
        if issuer.is_empty() {
            issues.push(ValidationIssue {
                field: "token.issuer".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
    }
    if let Some(ttl) = &token.access_token_ttl {
        if types::parse_duration_to_micros(ttl).is_err() {
            issues.push(ValidationIssue {
                field: "token.access_token_ttl".to_string(),
                reason: "invalid duration format".to_string(),
            });
        }
    }
    if let Some(ttl) = &token.refresh_token_ttl {
        if types::parse_duration_to_micros(ttl).is_err() {
            issues.push(ValidationIssue {
                field: "token.refresh_token_ttl".to_string(),
                reason: "invalid duration format".to_string(),
            });
        }
    }
}

/// Collects email validation issues without short-circuiting.
#[allow(clippy::too_many_lines)]
fn validate_email_all(email: &EmailConfig, issues: &mut Vec<ValidationIssue>) {
    if matches!(email.transport, EmailTransport::Log) {
        return;
    }

    // from address required for all non-log transports
    match &email.from {
        None => issues.push(ValidationIssue {
            field: "email.from".to_string(),
            reason: format!(
                "from address is required when email.transport is {:?}",
                email.transport
            ),
        }),
        Some(addr) => {
            if addr.parse::<lettre::message::Mailbox>().is_err() {
                issues.push(ValidationIssue {
                    field: "email.from".to_string(),
                    reason: "could not parse as an RFC 5322 mailbox".to_string(),
                });
            }
        }
    }

    match email.transport {
        EmailTransport::Smtp => {
            if let Some(smtp) = &email.smtp {
                if smtp.host.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.smtp.host".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
                if smtp.port == 0 {
                    issues.push(ValidationIssue {
                        field: "email.smtp.port".to_string(),
                        reason: "must be between 1 and 65535".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.smtp".to_string(),
                    reason: "smtp block is required when email.transport is smtp".to_string(),
                });
            }
        }
        EmailTransport::Sendgrid => {
            if let Some(sg) = &email.sendgrid {
                if sg.api_key.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.sendgrid.api_key".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.sendgrid".to_string(),
                    reason: "sendgrid block is required when email.transport is sendgrid"
                        .to_string(),
                });
            }
        }
        EmailTransport::Postmark => {
            if let Some(pm) = &email.postmark {
                if pm.server_token.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.postmark.server_token".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.postmark".to_string(),
                    reason: "postmark block is required when email.transport is postmark"
                        .to_string(),
                });
            }
        }
        EmailTransport::Mailgun => {
            if let Some(mg) = &email.mailgun {
                if mg.api_key.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.mailgun.api_key".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
                if mg.domain.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.mailgun.domain".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.mailgun".to_string(),
                    reason: "mailgun block is required when email.transport is mailgun".to_string(),
                });
            }
        }
        EmailTransport::Mailtrap => {
            if let Some(mt) = &email.mailtrap {
                if mt.api_key.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.mailtrap.api_key".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.mailtrap".to_string(),
                    reason: "mailtrap block is required when email.transport is mailtrap"
                        .to_string(),
                });
            }
        }
        EmailTransport::Log => unreachable!(),
    }
}

/// Collects branding validation issues without short-circuiting.
fn validate_branding_all(branding: &BrandingConfig, issues: &mut Vec<ValidationIssue>) {
    if let Some(theme) = &branding.theme {
        let lower = theme.to_ascii_lowercase();
        if !VALID_UI_THEMES.contains(&lower.as_str()) {
            issues.push(ValidationIssue {
                field: "branding.theme".to_string(),
                reason: format!(
                    "unknown theme '{}'; valid themes are: {}",
                    theme,
                    VALID_UI_THEMES.join(", ")
                ),
            });
        }
    }
    if let Some(path) = &branding.custom_css {
        if !std::fs::metadata(path)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            issues.push(ValidationIssue {
                field: "branding.custom_css".to_string(),
                reason: format!("file not found or not readable: {path}"),
            });
        }
    }
}

/// Collects per-realm web config validation issues.
fn validate_realm_web_configs_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (name, cfg) in realms {
        let Some(web) = &cfg.web else { continue };
        if let Some(theme) = &web.theme {
            let lower = theme.to_ascii_lowercase();
            if !VALID_UI_THEMES.contains(&lower.as_str()) {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.web.theme"),
                    reason: format!(
                        "unknown theme '{}'; valid themes are: {}",
                        theme,
                        VALID_UI_THEMES.join(", ")
                    ),
                });
            }
        }
        if let Some(path) = &web.custom_css {
            if !std::fs::metadata(path)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.web.custom_css"),
                    reason: format!("file not found or not readable: {path}"),
                });
            }
        }
    }
}

/// Collects per-realm auth config validation issues.
fn validate_realm_auth_configs_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (name, cfg) in realms {
        if let Some(scim) = &cfg.scim {
            if let Some(token) = &scim.bearer_token {
                if token.trim().is_empty() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.scim.bearer_token"),
                        reason: "must not be empty when SCIM is configured".to_string(),
                    });
                }
            }
        }
        let Some(auth) = &cfg.auth else { continue };
        if let Some(methods) = &auth.mfa_methods {
            for m in methods {
                if !VALID_MFA_METHODS.contains(&m.as_str()) {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.mfa_methods"),
                        reason: format!(
                            "unknown MFA method '{}'; valid methods are: {}",
                            m,
                            VALID_MFA_METHODS.join(", ")
                        ),
                    });
                }
            }
        }
        if let Some(methods) = &auth.allowed_auth_methods {
            for m in methods {
                if !VALID_AUTH_METHODS.contains(&m.as_str()) {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.allowed_auth_methods"),
                        reason: format!(
                            "unknown auth method '{}'; valid methods are: {}",
                            m,
                            VALID_AUTH_METHODS.join(", ")
                        ),
                    });
                }
            }
        }
        if let Some(pp) = &auth.password_policy {
            if let Some(len) = pp.min_length {
                if len == 0 {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.password_policy.min_length"),
                        reason: "must be >= 1".to_string(),
                    });
                }
            }
        }
        if let Some(token) = &auth.token {
            if let Some(ttl) = &token.access_token_ttl {
                if types::parse_duration_to_micros(ttl).is_err() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.token.access_token_ttl"),
                        reason: "invalid duration format".to_string(),
                    });
                }
            }
            if let Some(ttl) = &token.refresh_token_ttl {
                if types::parse_duration_to_micros(ttl).is_err() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.token.refresh_token_ttl"),
                        reason: "invalid duration format".to_string(),
                    });
                }
            }
        }
        if let Some(rl) = &auth.rate_limit {
            if let Some(dur) = &rl.lockout_duration {
                if types::parse_duration_to_micros(dur).is_err() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.rate_limit.lockout_duration"),
                        reason: "invalid duration format".to_string(),
                    });
                }
            }
        }
        if let Some(reg) = &auth.registration {
            if matches!(reg.mode, types::RegistrationModeYaml::DomainRestricted) {
                let missing = reg
                    .allowed_domains
                    .as_ref()
                    .map_or(true, std::vec::Vec::is_empty);
                if missing {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.registration.allowed_domains"),
                        reason:
                            "mode = domain_restricted requires a non-empty allowed_domains list"
                                .to_string(),
                    });
                }
            }
        }
    }
}

/// Collects per-realm application validation issues.
fn validate_realm_applications_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (realm_name, cfg) in realms {
        let Some(apps) = &cfg.applications else {
            continue;
        };
        for (app_key, app) in apps {
            let prefix = format!("realms.{realm_name}.applications.{app_key}");
            if app.name.trim().is_empty() {
                issues.push(ValidationIssue {
                    field: format!("{prefix}.name"),
                    reason: "must not be empty".to_string(),
                });
            }
            if let Some(grant_types) = &app.grant_types {
                for gt in grant_types {
                    if !VALID_GRANT_TYPES.contains(&gt.as_str()) {
                        issues.push(ValidationIssue {
                            field: format!("{prefix}.grant_types"),
                            reason: format!(
                                "unknown grant type '{}'; valid types are: {}",
                                gt,
                                VALID_GRANT_TYPES.join(", ")
                            ),
                        });
                    }
                }
            }
            match &app.redirect_uris {
                None => {
                    issues.push(ValidationIssue {
                        field: format!("{prefix}.redirect_uris"),
                        reason: "at least one redirect URI is required".to_string(),
                    });
                }
                Some(uris) if uris.is_empty() => {
                    issues.push(ValidationIssue {
                        field: format!("{prefix}.redirect_uris"),
                        reason: "at least one redirect URI is required".to_string(),
                    });
                }
                Some(uris) => {
                    for uri in uris {
                        if uri.is_empty() {
                            issues.push(ValidationIssue {
                                field: format!("{prefix}.redirect_uris"),
                                reason: "redirect URIs must not be empty strings".to_string(),
                            });
                        }
                    }
                }
            }
            let is_confidential = app.confidential.unwrap_or(false);
            if is_confidential && app.client_secret.is_none() {
                issues.push(ValidationIssue {
                    field: format!("{prefix}.client_secret"),
                    reason: "client_secret is required when confidential is true".to_string(),
                });
            }
            if !is_confidential && app.client_secret.is_some() {
                issues.push(ValidationIssue {
                    field: format!("{prefix}.confidential"),
                    reason: "confidential must be true when client_secret is provided".to_string(),
                });
            }
        }
    }
}

/// Collects per-realm organization validation issues.
fn validate_realm_organizations_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (realm_name, cfg) in realms {
        let Some(orgs) = &cfg.organizations else {
            continue;
        };
        for (slug, org) in orgs {
            let prefix = format!("realms.{realm_name}.organizations.{slug}");
            if org.name.trim().is_empty() {
                issues.push(ValidationIssue {
                    field: format!("{prefix}.name"),
                    reason: "must not be empty".to_string(),
                });
            }
            if slug.len() < 3 || slug.len() > 63 {
                issues.push(ValidationIssue {
                    field: prefix.clone(),
                    reason: format!("slug '{slug}' must be 3-63 characters"),
                });
            }
            if !slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                issues.push(ValidationIssue {
                    field: prefix.clone(),
                    reason: format!(
                        "slug '{slug}' must contain only lowercase letters, digits, and hyphens"
                    ),
                });
            }
            if slug.starts_with('-') || slug.ends_with('-') {
                issues.push(ValidationIssue {
                    field: prefix,
                    reason: format!("slug '{slug}' must not start or end with a hyphen"),
                });
            }
        }
    }
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
        assert_eq!(config.storage.hot_tier_capacity, Some(5000));
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
        assert_eq!(config.storage.hot_tier_capacity, None);
        assert_eq!(config.storage.hot_tier_max_memory, None);
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

        std::fs::write(
            dir.path().join(".env"),
            "HEARTH_FFILE_PRIORITY=from_dotenv\n",
        )
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
